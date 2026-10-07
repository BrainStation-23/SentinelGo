package collector

// Fuzz targets for the OS-agnostic log parsers. Any local user can write to
// journald/syslog (`logger "..."`) and the agent runs as root, so these parsers
// handle attacker-controlled bytes: they must never panic, and must return
// well-formed values for any input.
//
// The seed corpus below runs as an ordinary unit test under `go test ./...`.
// To actually fuzz one target:
//
//	go test -run='^$' -fuzz='^FuzzParseJournalLine$' -fuzztime=1m ./internal/auditlogs/collector/

import (
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// hostileJSONSeeds are malformed or adversarial inputs shared by the JSON-line targets.
var hostileJSONSeeds = []string{
	``,
	`{}`,
	`null`,
	`[]`,
	`"string"`,
	`{"MESSAGE":`,
	`{"MESSAGE":null,"PRIORITY":7}`,
	`{"MESSAGE":[-1,256,99999999999]}`,
	`{"MESSAGE":[0,0,0],"__CURSOR":[115]}`,
	`{"__REALTIME_TIMESTAMP":"-9223372036854775808"}`,
	`{"__REALTIME_TIMESTAMP":"99999999999999999999999"}`,
	`{"timestamp":"9999-99-99 99:99:99.999999-9999","eventMessage":"x"}`,
	`{"messageType":{"nested":true},"eventMessage":["a"]}`,
	strings.Repeat(`{"a":`, 2000) + strings.Repeat(`}`, 2000),
	"{\"MESSAGE\":\"\xff\xfe\xfd\"}",
	"{\"MESSAGE\":\"nul\\u0000byte\"}",
}

func FuzzParseJournalLine(f *testing.F) {
	f.Add([]byte(`{"__REALTIME_TIMESTAMP":"1700000000000000","__CURSOR":"s=abc;i=1",` +
		`"MESSAGE":"Accepted password for root","PRIORITY":"6","SYSLOG_IDENTIFIER":"sshd",` +
		`"_SYSTEMD_UNIT":"ssh.service","_PID":"1234","_UID":"0","_HOSTNAME":"host"}`))
	f.Add([]byte(`{"MESSAGE":[104,105],"PRIORITY":"6"}`))
	for _, s := range hostileJSONSeeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, line []byte) {
		entry, cursor, ok := parseJournalLine(line)
		if !ok {
			if !reflect.DeepEqual(entry, RawLogEntry{}) || cursor != "" {
				t.Fatalf("ok=false must return zero values, got entry=%+v cursor=%q", entry, cursor)
			}
			return
		}
		if entry.Source != "journal" {
			t.Fatalf("Source = %q, want journal", entry.Source)
		}
		if entry.Metadata == nil {
			t.Fatal("Metadata must be non-nil on success")
		}
	})
}

func FuzzParseMacLogShowLine(f *testing.F) {
	f.Add([]byte(`{"timestamp":"2024-04-19 14:30:00.123456-0700","messageType":"Error",` +
		`"eventMessage":"authentication failed","category":"auth","subsystem":"com.apple.security",` +
		`"process":"loginwindow"}`))
	f.Add([]byte(`{"foo":"bar"}`))
	for _, s := range hostileJSONSeeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, line []byte) {
		entry, ok := parseMacLogShowLine(line)
		if !ok {
			if !reflect.DeepEqual(entry, RawLogEntry{}) {
				t.Fatalf("ok=false must return a zero entry, got %+v", entry)
			}
			return
		}
		if entry.Source != "oslog" {
			t.Fatalf("Source = %q, want oslog", entry.Source)
		}
		if entry.Metadata == nil {
			t.Fatal("Metadata must be non-nil on success")
		}
		assertSeverityIn(t, entry.Severity, "2", "3", "5", "6", "7")
	})
}

// hostileLineSeeds are adversarial plain-text log lines.
var hostileLineSeeds = []string{
	``,
	`x`,
	`Jan`,
	`Jan  2 15:04:0`,
	`Feb 30 25:61:61 host app: impossible date`,
	`0000-00-00T00:00:00`,
	`9999-12-31T23:59:59+14:00 far future`,
	`-292277022657-01-27T08:29:52Z`,
	"\xff\xfe\xfd\x00\x01",
	strings.Repeat("A", 1<<20),
	"ERROR\x00WARN\x00PANIC",
}

func FuzzSyslogLine(f *testing.F) {
	f.Add("Jan  2 15:04:05 host sshd[1]: connection error")
	f.Add("Jan 12 15:04:05 host kernel: warning: low memory")
	f.Add("2024-04-19T14:30:00 host app: critical failure")
	f.Add("2024-04-19T14:30:00Z host app: emergency")
	for _, s := range hostileLineSeeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		_ = parseSyslogTimestamp(line)
		assertSeverityIn(t, inferSyslogSeverity(line), "0", "2", "3", "4", "6")
	})
}

func FuzzMacFileLine(f *testing.F) {
	f.Add("Apr 19 14:30:00 MacBook loginwindow[123]: authentication failed")
	f.Add("2024-04-19 14:30:00.123456-0700")
	f.Add("Default")
	f.Add("Fault")
	for _, s := range hostileLineSeeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		_ = parseMacFileTimestamp(line)
		_ = parseMacShowTimestamp(line)
		assertSeverityIn(t, inferMacSeverity(line), "2", "3", "4", "6")
		assertSeverityIn(t, macMessageTypeToSeverity(line), "2", "3", "5", "6", "7")
	})
}

// FuzzCheckpointInt64 feeds every value type a checkpoint can hold after a JSON
// round-trip (float64, numeric string, json-ish int64) through both accessors.
func FuzzCheckpointInt64(f *testing.F) {
	f.Add(float64(12345), "12345", int64(12345))
	f.Add(0.0, "", int64(0))
	f.Add(-1.5, "-1", int64(-1))
	f.Add(math.NaN(), "NaN", int64(math.MinInt64))
	f.Add(math.Inf(1), "Inf", int64(math.MaxInt64))
	f.Add(math.Inf(-1), "-Inf", int64(math.MinInt64))
	f.Add(9.223372036854775807e18, "9223372036854775808", int64(math.MaxInt64))
	f.Add(-9.223372036854775808e18, "-9223372036854775809", int64(math.MinInt64))
	f.Add(1e300, "1e300", int64(1))
	f.Add(math.SmallestNonzeroFloat64, "0x1p-1074", int64(0))

	f.Fuzz(func(t *testing.T, fl float64, s string, i int64) {
		cp := CheckpointData{"f": fl, "s": s, "i": i}

		if got, ok := CheckpointInt64(cp, "f"); ok {
			if math.IsNaN(fl) || math.IsInf(fl, 0) || fl < math.MinInt64 || fl >= math.MaxInt64 {
				t.Fatalf("CheckpointInt64(%v) = %d, true; want ok=false for a non-representable float", fl, got)
			}
			if got != int64(fl) {
				t.Fatalf("CheckpointInt64(%v) = %d, want %d", fl, got, int64(fl))
			}
		}
		if got, ok := CheckpointInt64(cp, "s"); ok {
			if want, err := strconv.ParseInt(s, 10, 64); err != nil || got != want {
				t.Fatalf("CheckpointInt64(%q) = %d, true; ParseInt gives %d, %v", s, got, want, err)
			}
		}
		if got, ok := CheckpointInt64(cp, "i"); !ok || got != i {
			t.Fatalf("CheckpointInt64(int64 %d) = %d, %v", i, got, ok)
		}

		for _, key := range []string{"f", "s", "i"} {
			if got, ok := CheckpointFloat64(cp, key); ok && (math.IsNaN(got) || math.IsInf(got, 0)) {
				t.Fatalf("CheckpointFloat64(%q) = %v, true; want ok=false for non-finite values", key, got)
			}
		}
	})
}

func assertSeverityIn(t *testing.T, got string, allowed ...string) {
	t.Helper()
	for _, a := range allowed {
		if got == a {
			return
		}
	}
	t.Fatalf("severity %q not in %v", got, allowed)
}
