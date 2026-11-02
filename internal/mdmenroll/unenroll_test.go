package mdmenroll

import (
	"context"
	"errors"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

func TestUnenroll(t *testing.T) {
	var removed []string
	newU := func(info *shared.MDMInfo) *Unenroller {
		return &Unenroller{
			OurHost:    func() string { return "mdm.example.com" },
			Collect:    func(string) *shared.MDMInfo { return info },
			Unregister: func(id string) error { removed = append(removed, id); return nil },
		}
	}
	intune := shared.MDMEnrollment{ID: "BBBBBBBB-0000-0000-0000-000000000002", ServerHost: "enrollment.manage.microsoft.com"}
	ours := shared.MDMEnrollment{ID: ourEnrollment, ServerHost: "mdm.example.com"}

	out, err := newU(windowsInfo(intune, ours)).Unenroll(context.Background(), "")
	if err != nil || out.Code != ResultUnenrolled || len(removed) != 1 || removed[0] != ourEnrollment {
		t.Fatalf("out %v err %v removed %v", out, err, removed)
	}
	removed = nil
	if _, err := newU(windowsInfo(intune)).Unenroll(context.Background(), ""); outcomeCode(t, err) != ResultNotEnrolled || len(removed) != 0 {
		t.Errorf("another MDM's enrollment: %v, removed %v", err, removed)
	}
	u := newU(windowsInfo(ours))
	u.Unregister = func(string) error { return errors.New("0x80180026") }
	if _, err := u.Unenroll(context.Background(), ""); err == nil {
		t.Error("a failed unregister reported success")
	}
	u = newU(&shared.MDMInfo{})
	if _, err := u.Unenroll(context.Background(), ""); outcomeCode(t, err) != ResultUnsupportedOS {
		t.Errorf("mac: %v", err)
	}
	u.Unregister = nil
	if _, err := u.Unenroll(context.Background(), ""); outcomeCode(t, err) != ResultUnsupportedOS {
		t.Errorf("no unregister: %v", err)
	}
}
