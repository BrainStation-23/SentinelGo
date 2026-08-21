package telemetry

import (
	"log"

	"sentinelgo/internal/sanitize"
	"sentinelgo/internal/store"
	tel "sentinelgo/internal/telemetry"
)

// watchedStateAdapter adapts the SQLite watched-state table to
// tel.WatchedStateStore.
//
// The encode/decode of the value itself happens here rather than in the store,
// keeping the store free of any knowledge of the telemetry value model — the
// same separation the section-state adapter maintains.
type watchedStateAdapter struct {
	s *store.TelemetryStateStore
}

func (a watchedStateAdapter) GetAll() (map[string]*tel.WatchedState, error) {
	rows, err := a.s.GetAllWatched()
	if err != nil {
		return nil, err
	}

	out := make(map[string]*tel.WatchedState, len(rows))
	for key, r := range rows {
		value, decodeErr := tel.DecodeValue(r.ValueJSON)
		if decodeErr != nil {
			// A row that cannot be decoded is worse than a missing one: it
			// would compare unequal to everything and fire an event every
			// cycle. Dropping it re-seeds that single baseline (one silent
			// cycle for one watch key) instead.
			log.Printf("[telemetry] discarding undecodable watched state %s: %v",
				sanitize.ForLog(key), decodeErr)
			if delErr := a.s.DeleteWatched(key); delErr != nil {
				log.Printf("[telemetry] delete undecodable watched state %s: %v",
					sanitize.ForLog(key), delErr)
			}
			continue
		}

		state := &tel.WatchedState{
			Key:             r.Key,
			Section:         r.Section,
			Value:           value,
			ObservedAt:      r.ObservedAt,
			ChangedAt:       r.ChangedAt,
			PendingSince:    r.PendingSince,
			LastEventAt:     r.LastEventAt,
			FlapCount:       r.FlapCount,
			FlapWindowStart: r.FlapWindowStart,
			FlapAlertedAt:   r.FlapAlertedAt,
		}
		if r.PendingJSON != "" {
			// A pending candidate that will not decode is simply dropped: the
			// worst case is that a Normal-priority change waits one more cycle
			// for confirmation, which is exactly the debounce rule anyway.
			if pending, pErr := tel.DecodeValue(r.PendingJSON); pErr == nil {
				state.Pending = pending
			}
		}
		out[key] = state
	}
	return out, nil
}

func (a watchedStateAdapter) Put(state *tel.WatchedState) error {
	if state == nil {
		return nil
	}

	valueJSON, err := state.Value.Encode()
	if err != nil {
		return err
	}

	pendingJSON := ""
	if state.HasPending() {
		pendingJSON, err = state.Pending.Encode()
		if err != nil {
			return err
		}
	}

	return a.s.PutWatched(&store.WatchedStateRow{
		Key:             state.Key,
		Section:         state.Section,
		ValueJSON:       valueJSON,
		ObservedAt:      state.ObservedAt,
		ChangedAt:       state.ChangedAt,
		PendingJSON:     pendingJSON,
		PendingSince:    state.PendingSince,
		LastEventAt:     state.LastEventAt,
		FlapCount:       state.FlapCount,
		FlapWindowStart: state.FlapWindowStart,
		FlapAlertedAt:   state.FlapAlertedAt,
	})
}

func (a watchedStateAdapter) Delete(key string) error { return a.s.DeleteWatched(key) }
