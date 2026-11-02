package mdmenroll

import (
	"context"
	"fmt"

	"sentinelgo/internal/osinfo/mdm"
	"sentinelgo/internal/osinfo/shared"
)

// ResultUnenrolled is mdm-unenroll's success.
const ResultUnenrolled = "unenrolled"

// Unenroller runs mdm-unenroll (#356): remove this deployment's MDM
// enrollment, and only when the console asks. Another MDM's enrollment is
// never touched, and uninstalling the agent doesn't unenroll.
type Unenroller struct {
	OurHost    func() string
	Collect    func(ourHost string) *shared.MDMInfo
	Unregister func(enrollmentID string) error
}

// NewUnenroller returns the platform's unenroller.
func NewUnenroller(ourHost func() string) *Unenroller {
	return &Unenroller{OurHost: ourHost, Collect: mdm.Collect, Unregister: UnregisterWindows}
}

// Unenroll removes our enrollment.
func (u *Unenroller) Unenroll(_ context.Context, mdmHost string) (Outcome, error) {
	host := mdmHost
	if host == "" && u.OurHost != nil {
		host = u.OurHost()
	}
	if u.Unregister == nil {
		return Outcome{}, fail(ResultUnsupportedOS, "unenrolling from MDM isn't supported on this platform")
	}
	info := u.Collect(host)
	if info == nil || info.Eligible == nil {
		return Outcome{}, fail(ResultUnsupportedOS, "unenrolling from MDM isn't supported on this platform")
	}
	if host == "" {
		return Outcome{}, fail(ResultMDMHostUnknown, "mdm_host isn't set, so the agent can't tell which enrollment is this deployment's")
	}
	for _, e := range info.Enrollments {
		if !mdm.IsOurServer(e.ServerHost, host) {
			continue
		}
		if err := u.Unregister(e.ID); err != nil {
			return Outcome{}, fmt.Errorf("mdm-unenroll: removing enrollment %s: %w", e.ID, err)
		}
		return Outcome{ResultUnenrolled, "removed this deployment's MDM enrollment " + e.ID}, nil
	}
	return Outcome{}, fail(ResultNotEnrolled, "the device isn't enrolled in this deployment's MDM")
}
