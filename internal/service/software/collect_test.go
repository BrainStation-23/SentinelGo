package software

import "testing"

// stubPlatformSoftware replaces the per-OS collector for the duration of a test,
// recording the receiver it was invoked with.
func stubPlatformSoftware(t *testing.T, list []SoftwareInfo, complete bool) *[]*SoftwareService {
	t.Helper()
	var calls []*SoftwareService
	orig := platformSoftwareFn
	t.Cleanup(func() { platformSoftwareFn = orig })
	platformSoftwareFn = func(s *SoftwareService) ([]SoftwareInfo, bool) {
		calls = append(calls, s)
		return list, complete
	}
	return &calls
}

func TestGetSoftwareListWithStatus_ReturnsCollectorResult(t *testing.T) {
	for _, complete := range []bool{true, false} {
		want := []SoftwareInfo{{Name: "a", Source: "programs"}, {Name: "b", Source: "deb_packages"}}
		calls := stubPlatformSoftware(t, want, complete)
		svc := NewSoftwareService()

		got, gotComplete := svc.GetSoftwareListWithStatus()
		if gotComplete != complete {
			t.Errorf("complete = %v, want %v", gotComplete, complete)
		}
		if len(got) != len(want) || got[0].Name != "a" || got[1].Name != "b" {
			t.Errorf("list = %+v, want %+v", got, want)
		}
		if len(*calls) != 1 || (*calls)[0] != svc {
			t.Errorf("collector calls = %v, want exactly one with the service as receiver", *calls)
		}
	}
}

// GetSoftwareList drops the completeness flag: a partial scan still returns its
// (partial) list rather than nil.
func TestGetSoftwareList_DropsCompleteFlag(t *testing.T) {
	stubPlatformSoftware(t, []SoftwareInfo{{Name: "partial"}}, false)

	got := NewSoftwareService().GetSoftwareList()
	if len(got) != 1 || got[0].Name != "partial" {
		t.Errorf("GetSoftwareList() = %+v, want the partial list", got)
	}
}

func TestGetSoftwareList_EmptyCollector(t *testing.T) {
	stubPlatformSoftware(t, nil, true)

	if got := NewSoftwareService().GetSoftwareList(); len(got) != 0 {
		t.Errorf("GetSoftwareList() = %+v, want empty", got)
	}
}
