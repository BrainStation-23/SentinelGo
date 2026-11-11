package policy

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestUploadInspection_Decode(t *testing.T) {
	var m FilesModule
	raw := `{"enabled": true, "channels": {"file.upload": true},
	  "uploads": {"inspection": {"enabled": true,
	    "intercept": ["Drive.Google.com", "*.dropbox.com", "chat.example.ai.", "bad host", "x\");alert(1);//.com", "nodot", "*.dropbox.com", ""],
	    "bypass": ["bank.example.com", "-bad-.example.com"]}}}`
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	m.normalize()
	in := m.Uploads.Inspection
	if want := []string{"drive.google.com", "*.dropbox.com", "chat.example.ai"}; !reflect.DeepEqual(in.Intercept, want) {
		t.Errorf("intercept %q", in.Intercept)
	}
	if want := []string{"bank.example.com"}; !reflect.DeepEqual(in.Bypass, want) {
		t.Errorf("bypass %q", in.Bypass)
	}
	if !m.InspectsUploads() {
		t.Error("inspection should be on")
	}
	m.Channels[ChannelFileUpload] = false
	if m.InspectsUploads() {
		t.Error("on without the upload channel")
	}
}

func TestUploadInspection_DirectBlock(t *testing.T) {
	for raw, want := range map[string]string{
		``:                          DirectBlockQUIC,
		`"direct_block": "quic",`:   DirectBlockQUIC,
		`"direct_block": "Strict",`: DirectBlockStrict,
		`"direct_block": " off ",`:  DirectBlockOff,
		`"direct_block": "tcp",`:    DirectBlockQUIC,
		`"direct_block": "",`:       DirectBlockQUIC,
	} {
		var m FilesModule
		if err := json.Unmarshal([]byte(`{"enabled": true, "channels": {"file.upload": true},
		  "uploads": {"inspection": {"enabled": true, `+raw+` "intercept": ["a.example.com"]}}}`), &m); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		m.normalize()
		if in := m.Uploads.Inspection; in.Mode() != want || in.DirectBlock != want {
			t.Errorf("%s: mode %q, field %q, want %q", raw, in.Mode(), in.DirectBlock, want)
		}
	}
	// A wrong type turns inspection off (DecodeError), as for any bad field.
	var m FilesModule
	_ = json.Unmarshal([]byte(`{"enabled": true, "uploads": {"inspection": {"enabled": true, "direct_block": 1, "intercept": ["a.example.com"]}}}`), &m)
	m.normalize()
	if m.Uploads.Inspection.Enabled || m.Uploads.Inspection.Mode() != DirectBlockQUIC {
		t.Errorf("wrong type: %+v", m.Uploads.Inspection)
	}
}

func TestUploadInspection_OffCases(t *testing.T) {
	for name, raw := range map[string]string{
		"absent":        `{"enabled": true, "channels": {"file.upload": true}}`,
		"no hosts":      `{"enabled": true, "channels": {"file.upload": true}, "uploads": {"inspection": {"enabled": true, "intercept": ["bad host"]}}}`,
		"unreadable":    `{"enabled": true, "channels": {"file.upload": true}, "uploads": {"inspection": {"enabled": "yes"}}}`,
		"not enabled":   `{"enabled": true, "channels": {"file.upload": true}, "uploads": {"inspection": {"intercept": ["a.example.com"]}}}`,
		"module is off": `{"enabled": false, "channels": {"file.upload": true}, "uploads": {"inspection": {"enabled": true, "intercept": ["a.example.com"]}}}`,
	} {
		var m FilesModule
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		m.normalize()
		if m.InspectsUploads() {
			t.Errorf("%s: inspection on", name)
		}
		if name == "unreadable" && (m.Uploads.Inspection.DecodeError == "" || !m.Enabled) {
			t.Errorf("an unreadable block must only turn inspection off: %+v", m)
		}
	}
}
