package parser

import (
	"encoding/json"
	"sort"
	"unicode/utf8"
)

// DefaultMaxEventDataBytes is the server's limit on one row's serialized
// event_data until the enqueue response says otherwise (#438). Rows over it
// are rejected server-side and the event is lost.
const DefaultMaxEventDataBytes = 10_000

// EventDataTarget is the size event_data is trimmed to for a server limit of
// maxBytes: 5% under it, so the server's own encoding never tips a row over.
// maxBytes <= 0 means the default limit.
func EventDataTarget(maxBytes int) int {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxEventDataBytes
	}
	return maxBytes - maxBytes/20
}

// keptKeys identify the event and are never trimmed.
var keptKeys = map[string]bool{
	"event_id":         true,
	"provider":         true,
	"channel":          true,
	"record_id":        true,
	"computer":         true,
	"timestamp_source": true,
	"truncated":        true,
	"original_bytes":   true,
}

// CapEventData returns data unchanged when it fits in target bytes. Otherwise
// it trims the longest string values first (on a UTF-8 boundary), dropping a
// value only when trimming can't make room, and marks the result with
// "truncated": true and "original_bytes". The row itself is never dropped.
func CapEventData(data json.RawMessage, target int) json.RawMessage {
	if len(data) <= target {
		return data
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil || m == nil {
		b, _ := json.Marshal(map[string]any{"truncated": true, "original_bytes": len(data)})
		return b
	}
	m["truncated"] = true
	m["original_bytes"] = len(data)

	for {
		b, err := json.Marshal(m)
		if err != nil {
			return data
		}
		over := len(b) - target
		if over <= 0 {
			return b
		}
		key, s, ok := longestTrimmable(m)
		if !ok {
			// Only identifying keys are left; nothing more can go.
			return b
		}
		// JSON escaping can make a value take more bytes than its length, so
		// cut a little extra and check again on the next pass.
		keep := len(s) - over - 16
		if keep <= 0 {
			delete(m, key)
			continue
		}
		m[key] = truncateUTF8(s, keep)
	}
}

// longestTrimmable returns the longest value that may be trimmed, or, when no
// strings are left, any other value that may be dropped. Ties go to the key
// that sorts first, so the result is deterministic.
func longestTrimmable(m map[string]any) (key, val string, ok bool) {
	keys := make([]string, 0, len(m))
	for k := range m {
		if !keptKeys[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	best := -1
	for _, k := range keys {
		s, isStr := m[k].(string)
		if !isStr {
			continue
		}
		if len(s) > best {
			key, val, best = k, s, len(s)
		}
	}
	if best >= 0 {
		return key, val, true
	}
	if len(keys) > 0 {
		return keys[0], "", true
	}
	return "", "", false
}

// truncateUTF8 cuts s to at most n bytes without splitting a rune.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
