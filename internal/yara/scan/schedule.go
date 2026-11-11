package scan

import (
	"crypto/sha256"
	"encoding/binary"
	"time"

	"sentinelgo/internal/yara"
)

// Offset is the device's start offset for a schedule: a value in
// [0, jitterMinutes) derived from the agent id and the schedule id, so it is
// the same across restarts and differs between devices. A 5,000-device
// fleet with jitter_minutes 120 starts its scans spread over two hours, not
// all at once.
func Offset(agentID, scheduleID string, jitterMinutes int) time.Duration {
	if jitterMinutes <= 0 {
		return 0
	}
	sum := sha256.Sum256([]byte(agentID + "\x00" + scheduleID))
	span := uint64(jitterMinutes) * uint64(time.Minute/time.Second)
	return time.Duration(binary.BigEndian.Uint64(sum[:8])%span) * time.Second
}

// windowStart is the start of the period of t: periods are every_hours long,
// counted from the Unix epoch, shifted by the device's offset.
func windowStart(t time.Time, period, offset time.Duration) time.Time {
	base := time.Unix(0, 0).Add(offset)
	n := t.Sub(base) / period
	if t.Before(base.Add(n * period)) {
		n-- // before the epoch: round down, not toward zero
	}
	return base.Add(n * period)
}

// NextRun is when the schedule next runs on this device. A schedule never
// run here runs at the offset after the agent first saw it (a new schedule
// doesn't start on every device at once). After that it runs once per
// period, at the device's offset into the period, the first period after
// the last run.
func NextRun(s yara.Schedule, agentID string, seen, lastRun time.Time) time.Time {
	period := time.Duration(s.EveryHours) * time.Hour
	offset := Offset(agentID, s.ID, s.JitterMinutes)
	if period <= 0 {
		return time.Time{}.Add(1<<63 - 1) // never (Decode refuses this)
	}
	offset %= period
	if lastRun.IsZero() {
		return seen.Add(offset)
	}
	return windowStart(lastRun, period, offset).Add(period)
}
