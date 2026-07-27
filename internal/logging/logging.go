package logging

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"sentinelgo/internal/auditlogs/collector"
	"sentinelgo/internal/auditlogs/parser"
	"sentinelgo/internal/config"
	"sentinelgo/internal/sanitize"
	"sentinelgo/internal/store"
)

const (
	defaultMaxEntriesPerCycle = 1000
	realtimeChanSize          = 256
)

// LoggingIntegration orchestrates the full log collection pipeline:
// collector -> parser -> local SQLite store -> uploader -> Supabase.
//
// On each collection cycle the pipeline:
//  1. Records collectionTime = now and windowStart = now - flushInterval.
//  2. Collects raw OS log entries since the last checkpoint.
//  3. Filters entries to those with Timestamp >= windowStart (time-window bound).
//  4. Parses and inserts filtered entries into the local SQLite queue (dedup'd by hash).
//  5. Advances the checkpoint to the latest record seen (even for filtered-out entries).
//  6. Uploads all pending rows from the SQLite queue to Supabase, deleting successes.
//
// Failed uploads leave rows in the store and are retried on the next cycle.
type LoggingIntegration struct {
	cfg        *config.Config
	collector  collector.Collector
	parser     parser.Parser
	store      *store.AuditLogStore
	uploader   *Uploader
	checkpoint *CheckpointStore
	stats      statsCounter

	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.Mutex
	started bool
}

// NewLoggingIntegration creates a new logging integration from the given config.
// The collector is selected based on the current OS (via build tags).
// Opens the local audit log SQLite store in the same directory as the config file.
func NewLoggingIntegration(cfg *config.Config) (*LoggingIntegration, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	checkpointDir := filepath.Dir(cfg.Path)
	if checkpointDir == "" || checkpointDir == "." {
		checkpointDir = "/tmp/sentinelgo"
	}

	// Sanitize checkpoint directory path to prevent path traversal
	checkpointDir = filepath.Clean(checkpointDir)
	if !filepath.IsAbs(checkpointDir) {
		absPath, err := filepath.Abs(checkpointDir)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve absolute checkpoint directory: %w", err)
		}
		checkpointDir = absPath
	}

	sanitizedConfigPath := sanitize.ForLog(cfg.Path)
	sanitizedCheckpointDir := sanitize.ForLog(checkpointDir)
	log.Printf("[logging] Config path: %s", sanitizedConfigPath)
	log.Printf("[logging] Checkpoint directory: %s", sanitizedCheckpointDir)

	// Ensure checkpoint directory exists
	if err := os.MkdirAll(checkpointDir, 0750); err != nil {
		return nil, fmt.Errorf("create checkpoint directory: %w", err)
	}

	cpStore := NewCheckpointStore(checkpointDir)

	dbPath := filepath.Join(checkpointDir, "auditlogs.sqlite")
	sanitizedDbPath := sanitize.ForLog(dbPath)
	log.Printf("[logging] Database path: %s", sanitizedDbPath)

	auditStore, err := store.NewAuditLogStore(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open audit log store: %w", err)
	}

	li := &LoggingIntegration{
		cfg:        cfg,
		collector:  collector.NewCollector(),
		parser:     parser.NewParser(),
		store:      auditStore,
		checkpoint: cpStore,
	}
	li.uploader = NewUploader(cfg, &li.stats)

	log.Printf("[logging] Logging integration created successfully")
	return li, nil
}

// SetAuth wires an auth recovery handle into the uploader so audit-log uploads
// react to 401s (refresh→login) and pause while the session is unrecoverable.
func (li *LoggingIntegration) SetAuth(auth authRetrier) {
	li.uploader.SetAuth(auth)
}

// Start begins the background collection and upload loops.
func (li *LoggingIntegration) Start(ctx context.Context) error {
	li.mu.Lock()
	defer li.mu.Unlock()

	if li.started {
		return nil
	}

	if err := li.checkpoint.Load(); err != nil {
		log.Printf("[logging] warning: failed to load checkpoints, starting fresh: %v", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	li.cancel = cancel
	li.started = true

	li.wg.Add(1)
	go li.collectionLoop(ctx)

	li.wg.Add(1)
	go li.subscriptionLoop(ctx)

	log.Printf("[logging] started (flush_interval=%s, sources=%v)",
		li.cfg.GetLogFlushInterval(), li.collector.Sources())
	return nil
}

// Stop gracefully shuts down collection, uploads any remaining pending logs, and
// closes the local store.
func (li *LoggingIntegration) Stop() error {
	li.mu.Lock()
	defer li.mu.Unlock()

	if !li.started {
		return nil
	}

	li.cancel()
	li.wg.Wait()
	li.started = false

	// Final upload attempt: drain whatever is still in the store.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if n, err := li.uploader.UploadFromStore(ctx, li.store); err != nil {
		log.Printf("[logging] final flush partial: uploaded %d logs: %v", n, err)
	}

	if err := li.store.Close(); err != nil {
		log.Printf("[logging] warning: failed to close audit log store: %v", err)
	}

	if err := li.checkpoint.Save(); err != nil {
		log.Printf("[logging] warning: failed to save checkpoint on stop: %v", err)
	}

	log.Printf("[logging] stopped")
	return nil
}

// CollectLogsNow triggers an immediate collection cycle.
func (li *LoggingIntegration) CollectLogsNow(ctx context.Context) error {
	return li.runCollection(ctx)
}

// ForceUpload uploads all pending logs from the store immediately.
func (li *LoggingIntegration) ForceUpload(ctx context.Context) error {
	n, err := li.uploader.UploadFromStore(ctx, li.store)
	log.Printf("[logging] force upload: %d logs sent", n)

	if n > 0 {
		if saveErr := li.checkpoint.Save(); saveErr != nil {
			log.Printf("[logging] warning: failed to save checkpoint: %v", saveErr)
		}
	}

	return err
}

// GetStatistics returns a snapshot of logging pipeline counters.
func (li *LoggingIntegration) GetStatistics() LoggingStats {
	return li.stats.snapshot()
}

// collectionLoop runs the periodic collection-and-upload cycle.
func (li *LoggingIntegration) collectionLoop(ctx context.Context) {
	defer li.wg.Done()

	interval := li.cfg.GetLogFlushInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := li.runCollection(ctx); err != nil {
				log.Printf("[logging] collection cycle error: %v", err)
			}

			if n, err := li.uploader.UploadFromStore(ctx, li.store); err != nil {
				log.Printf("[logging] upload error (uploaded %d): %v", n, err)
			} else if n > 0 {
				if err := li.checkpoint.Save(); err != nil {
					log.Printf("[logging] checkpoint save error: %v", err)
				}
			}
		}
	}
}

// subscriptionLoop handles real-time log events from the collector.
func (li *LoggingIntegration) subscriptionLoop(ctx context.Context) {
	defer li.wg.Done()

	ch := make(chan collector.RawLogEntry, realtimeChanSize)

	go func() {
		if err := li.collector.Subscribe(ctx, ch); err != nil {
			log.Printf("[logging] subscription error: %v", err)
		}
	}()

	parserCfg := li.parserConfig()

	for {
		select {
		case <-ctx.Done():
			return
		case raw, ok := <-ch:
			if !ok {
				return
			}
			parsed := li.parser.Parse([]collector.RawLogEntry{raw}, parserCfg)
			if len(parsed) == 0 {
				continue
			}
			if err := li.store.Insert(parsed); err != nil {
				log.Printf("[logging] real-time store insert error: %v", err)
			} else {
				li.stats.addCollected(int64(len(parsed)))
				li.stats.addStored(int64(len(parsed)))
			}
		}
	}
}

// maxDrainIterations bounds how many collect batches a single cycle will pull.
// It is a safety backstop against a collector that never reports "drained"
// (e.g. a source on a very busy host, or one whose checkpoint fails to advance).
// When the cap is hit, the persisted checkpoint guarantees the remaining backlog
// is picked up on the next cycle — nothing is lost, it is only deferred.
const maxDrainIterations = 100

// runCollection performs a single collection cycle, draining ALL entries
// available since the last checkpoint into the local SQLite queue.
//
// Correctness notes (audit fixes H1/H6 — this is a compliance agent, audit
// events must not be silently dropped):
//   - There is NO time-window filter. The previous implementation discarded any
//     entry older than now-flushInterval AFTER advancing the checkpoint past it,
//     so a downtime backlog (agent offline > flushInterval) was permanently lost.
//     The checkpoint/cursor is the single source of "what is new".
//   - The checkpoint is advanced ONLY after entries are durably stored, so a
//     store failure re-collects rather than skips. The SQLite store is the
//     at-least-once queue; the uploader drains it independently.
//   - Bursts larger than one batch are drained in a loop instead of being
//     truncated to a fixed cap, so high-volume periods are not silently dropped.
func (li *LoggingIntegration) runCollection(ctx context.Context) error {
	totalCollected := 0
	totalStored := 0
	cappedOut := false

	for iter := 0; iter < maxDrainIterations; iter++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		collectorCP := collector.CheckpointData(li.checkpoint.Get())

		entries, newCP, err := li.collector.Collect(ctx, collectorCP)
		if err != nil {
			return fmt.Errorf("collect: %w", err)
		}
		if len(entries) == 0 {
			break // drained: nothing new since the checkpoint
		}

		// Parse and persist BEFORE advancing the checkpoint. The store dedups by
		// hash, so a re-collect after a crash between Insert and checkpoint Save
		// produces no duplicates.
		parsed := li.parser.Parse(entries, li.parserConfig())
		if err := li.store.Insert(parsed); err != nil {
			return fmt.Errorf("store insert: %w", err)
		}

		// Advance the checkpoint past entries now durably stored. Update merges,
		// so per-source keys absent from newCP are preserved.
		li.checkpoint.Update(CheckpointData(newCP))

		totalCollected += len(entries)
		totalStored += len(parsed)

		if iter == maxDrainIterations-1 {
			cappedOut = true
		}
	}

	if totalCollected == 0 {
		return nil
	}

	// Persist the checkpoint now that entries are in the durable store, decoupled
	// from upload success — the uploader retries from the store independently.
	if err := li.checkpoint.Save(); err != nil {
		log.Printf("[logging] checkpoint save error after collection: %v", err)
	}

	li.stats.addCollected(int64(totalCollected))
	li.stats.addStored(int64(totalStored))

	if cappedOut {
		log.Printf("[logging] collected %d entries, %d stored (drain cap of %d batches hit; "+
			"remaining backlog continues next cycle, checkpoint persisted — no loss)",
			totalCollected, totalStored, maxDrainIterations)
	} else {
		log.Printf("[logging] collected %d entries, %d stored", totalCollected, totalStored)
	}

	return nil
}

// parserConfig builds a ParserConfig from the current agent config.
func (li *LoggingIntegration) parserConfig() parser.ParserConfig {
	return parser.ParserConfig{
		AgentID:      "",
		DeviceID:     li.cfg.DeviceID,
		OSType:       runtime.GOOS,
		AgentVersion: li.cfg.CurrentVersion,
	}
}
