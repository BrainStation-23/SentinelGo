package scan

// Benchmarks for #417: the scan pipeline (walk, open, match, hash, events)
// with the real go-yara engine in process, over a synthetic corpus, with 1,
// 10 and 50 rulesets. They measure the agent's own cost per file and per
// byte; a device's numbers (quick and full scan duration, CPU, RSS of the
// service and the worker) are measured on reference machines (docs/yara.md).
//
//	go test ./internal/yara/scan -run '^$' -bench Scan -benchmem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/yara"
	"sentinelgo/internal/yara/engine"
	"sentinelgo/internal/yara/ruleset"
	"sentinelgo/internal/yara/walk"
)

// engineScanner matches in process with compiled programs, hashing in the
// same pass, as the worker does.
type engineScanner struct{ progs []engine.Program }

func (s engineScanner) ScanFile(ctx context.Context, _ ruleset.Rules, f walk.File, _ []string, _ time.Duration) FileOutcome {
	fh, err := walk.Open(f)
	if err != nil {
		return FileOutcome{Status: ReadError}
	}
	defer func() { _ = fh.Close() }()
	h := sha256.New()
	var out FileOutcome
	for i, p := range s.progs {
		if _, err := fh.Seek(0, io.SeekStart); err != nil {
			return FileOutcome{Status: ReadError}
		}
		var r io.Reader = fh
		if i == 0 {
			r = io.TeeReader(fh, h)
		}
		ms, err := p.ScanReader(ctx, r, engine.File{Path: f.Path, Size: f.Size})
		if err != nil {
			return FileOutcome{Status: ReadError}
		}
		out.Matches = append(out.Matches, ms...)
	}
	out.Status, out.SHA256, out.Size = Scanned, hex.EncodeToString(h.Sum(nil)), f.Size
	return out
}

// benchRuleset is a typical hunting ruleset: 20 rules of text and hex
// strings with a filesize guard. One rule per ruleset matches the marker.
func benchRuleset(n int) []byte {
	var b strings.Builder
	for i := range 20 {
		fmt.Fprintf(&b, "rule r%d_%d {\n strings:\n  $a = \"suspicious-%d-%d\" ascii wide nocase\n  $b = { 4D 5A 90 00 %02X ?? 00 00 }\n condition:\n  filesize < 50MB and any of them\n}\n", n, i, n, i, i)
	}
	fmt.Fprintf(&b, "rule marker_%d {\n strings:\n  $m = %q\n condition:\n  $m\n}\n", n, marker)
	return []byte(b.String())
}

// benchCorpus writes files of 4 KB to 256 KB of random bytes, one in 50
// with the marker.
func benchCorpus(b *testing.B, n int) (dir string, total int64) {
	b.Helper()
	dir = b.TempDir()
	rng := rand.New(rand.NewPCG(1, 2))
	for i := range n {
		size := 4<<10 + rng.IntN(252<<10)
		data := make([]byte, size)
		for j := range data {
			data[j] = byte(rng.Uint32())
		}
		if i%50 == 0 {
			copy(data[size/2:], marker)
		}
		sub := filepath.Join(dir, fmt.Sprintf("d%02d", i%16))
		if err := os.MkdirAll(sub, 0o700); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sub, fmt.Sprintf("f%04d.bin", i)), data, 0o600); err != nil {
			b.Fatal(err)
		}
		total += int64(size)
	}
	return dir, total
}

type countQueue struct{ n int }

func (q *countQueue) Add(evs []yara.Event) error { q.n += len(evs); return nil }

func BenchmarkScan(b *testing.B) {
	log.SetOutput(io.Discard)
	b.Cleanup(func() { log.SetOutput(os.Stderr) })
	const files = 200
	dir, total := benchCorpus(b, files)
	for _, sets := range []int{1, 10, 50} {
		b.Run(fmt.Sprintf("rulesets=%d", sets), func(b *testing.B) {
			e := engine.New(engine.Options{})
			var progs []engine.Program
			a := bundle()
			a.Bundle.Rulesets = nil
			for i := range sets {
				id := fmt.Sprintf("%08x-0000-4000-8000-000000000000", i)
				p, skipped, err := e.Compile(context.Background(), id, benchRuleset(i))
				if err != nil || len(skipped) > 0 {
					b.Fatalf("compile: %v %v", err, skipped)
				}
				progs = append(progs, p)
				a.Bundle.Rulesets = append(a.Bundle.Rulesets, yara.Ruleset{ID: id, Revision: 1})
			}
			b.SetBytes(total)
			b.ResetTimer()
			for range b.N {
				q := &countQueue{}
				done := make(chan *yara.ScanSummary, 1)
				r := New(Options{Active: func() *ruleset.Active { return a }, Scanner: engineScanner{progs}, Queue: q,
					Env: walk.DefaultEnv(), OnScanEnd: func(s *yara.ScanSummary, _ bool) { done <- s }})
				if _, err := r.StartOnDemand(yara.TaskParams{Preset: yara.PresetCustom, Paths: []string{dir}}); err != nil {
					b.Fatal(err)
				}
				s := <-done
				if s.FilesScanned != files || s.Matches != int64(files/50*sets) {
					b.Fatalf("summary %+v", s)
				}
				r.Stop(time.Minute)
			}
			b.ReportMetric(float64(files*b.N)/b.Elapsed().Seconds(), "files/s")
		})
	}
}
