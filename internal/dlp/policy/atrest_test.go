package policy

import (
	"reflect"
	"testing"
)

func TestAtRest_Decode(t *testing.T) {
	m := decodeFiles(t, `{"enabled": true, "copy_correlation": {"process_taint": true}, "at_rest": {"enabled": true,
	  "folders": {"windows": ["~\\Documents", " ~\\documents ", "", "D:\\Shared\\*"]},
	  "exclude": {"windows": ["~\\Documents\\Archive"]},
	  "max_cpu_percent": 90, "skip_on_battery": false, "rescan_hours": 2}}`)
	a := m.AtRest
	if !m.WantsAtRest() || !m.ClassifiesAtRest("windows") {
		t.Fatalf("wants %v classifies %v", m.WantsAtRest(), m.ClassifiesAtRest("windows"))
	}
	if want := []string{`~\Documents`, `D:\Shared\*`}; !reflect.DeepEqual(a.FoldersFor("windows"), want) {
		t.Errorf("folders %q", a.FoldersFor("windows"))
	}
	if a.MaxCPUPercent != MaxAtRestCPUPercent || a.RescanHours != MinAtRestRescanHours || a.PausesOnBattery() {
		t.Errorf("limits %+v", a)
	}
	if len(a.Exclude["windows"]) != 1 {
		t.Errorf("exclude %q", a.Exclude)
	}
}

func TestAtRest_Defaults(t *testing.T) {
	m := decodeFiles(t, `{"enabled": true, "at_rest": {"enabled": true}}`)
	a := m.AtRest
	if a.MaxCPUPercent != DefaultAtRestCPUPercent || a.RescanHours != DefaultAtRestRescanHours || !a.PausesOnBattery() {
		t.Errorf("defaults %+v", a)
	}
	if !reflect.DeepEqual(a.FoldersFor("windows"), DefaultAtRestFolders["windows"]) || a.FoldersFor("linux") != nil {
		t.Errorf("default folders %q / %q", a.FoldersFor("windows"), a.FoldersFor("linux"))
	}
	// Nothing uses the verdicts without process taint or taint blocks.
	if !m.WantsAtRest() || m.ClassifiesAtRest("windows") {
		t.Errorf("wants %v classifies %v", m.WantsAtRest(), m.ClassifiesAtRest("windows"))
	}
	// Taint blocks use them too.
	m = decodeFiles(t, `{"enabled": true, "at_rest": {"enabled": true},
	  "network_control": {"enabled": true, "taint_block": {"enabled": true}}}`)
	if !m.ClassifiesAtRest("windows") {
		t.Error("taint blocks should use at-rest verdicts")
	}
}

func TestAtRest_OffWhenAbsentOrUnreadable(t *testing.T) {
	if m := decodeFiles(t, `{"enabled": true}`); m.WantsAtRest() {
		t.Error("absent should be off")
	}
	m := decodeFiles(t, `{"enabled": true, "channels": {"file.removable": true}, "at_rest": {"enabled": true, "folders": "C:\\"}}`)
	if m.WantsAtRest() || m.AtRest.DecodeError == "" {
		t.Errorf("unreadable block: wants %v error %q", m.WantsAtRest(), m.AtRest.DecodeError)
	}
	if !m.ChannelEnabled("file.removable") {
		t.Error("an unreadable at_rest block must not turn file DLP off")
	}
	if m = decodeFiles(t, `{"enabled": false, "at_rest": {"enabled": true}}`); m.WantsAtRest() {
		t.Error("module off should turn it off")
	}
}
