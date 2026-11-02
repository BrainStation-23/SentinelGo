package mdm

import "testing"

// The real collector runs on any Windows: it reports an edition, and an
// eligibility that matches it (CI runners are Windows Server, so
// ineligible there).
func TestCollect_Windows(t *testing.T) {
	info := collect("mdm.example.com")
	if info == nil || info.Edition == "" || info.Eligible == nil {
		t.Fatalf("info = %+v", info)
	}
	if !*info.Eligible && info.IneligibleReason == "" {
		t.Error("ineligible without a reason")
	}
	t.Logf("edition %s eligible %v (%s) enrolled %v smbios %s", info.Edition, *info.Eligible, info.IneligibleReason, info.Enrolled, info.Identity.SMBIOSUUID)
}
