package events

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFileName_EvidenceModes(t *testing.T) {
	for _, tc := range []struct {
		mode, path string
		want       *string
	}{
		{"none", `C:\Users\jdoe\Documents\salary_review.xlsx`, nil},
		{"masked", `C:\Users\jdoe\Documents\salary_review.xlsx`, ptr("salary_review.xlsx")},
		{"masked", "/home/jdoe/export.csv", ptr("export.csv")},
		{"", "/home/jdoe/export.csv", ptr("export.csv")}, // unknown mode: masked
		{"masked", "report.pdf", ptr("report.pdf")},
		{"full", "/home/jdoe/export.csv", ptr("/home/jdoe/export.csv")},
	} {
		got := FileName(tc.mode, tc.path)
		if (got == nil) != (tc.want == nil) || got != nil && *got != *tc.want {
			t.Errorf("FileName(%q, %q) = %v, want %v", tc.mode, tc.path, deref(got), deref(tc.want))
		}
	}
}

func ptr(s string) *string { return &s }

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// Clipboard events must keep their exact shape: the file fields are only
// sent for file channels.
func TestEvent_ClipboardShapeUnchanged(t *testing.T) {
	raw, err := json.Marshal(Event{Channel: "clipboard", Findings: []Finding{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"file"`, `"destination"`, `"process"`, `"scan"`} {
		if strings.Contains(string(raw), key) {
			t.Errorf("clipboard event has %s: %s", key, raw)
		}
	}
	f := Event{Channel: "file.removable", File: &File{Name: nil, Ext: "xlsx", Size: 3},
		Destination: &Destination{Type: "removable", USB: &USB{VendorID: "0781"}},
		Scan:        &Scan{Status: "scanned", VerdictSource: "scan", DurationMs: 12}}
	raw, err = json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	// evidence_mode "none": the name is sent as null, not left out.
	if !strings.Contains(string(raw), `"file":{"name":null,"ext":"xlsx","size":3}`) ||
		!strings.Contains(string(raw), `"usb":{"vendor_id":"0781"}`) || !strings.Contains(string(raw), `"verdict_source":"scan"`) {
		t.Errorf("file event: %s", raw)
	}
}
