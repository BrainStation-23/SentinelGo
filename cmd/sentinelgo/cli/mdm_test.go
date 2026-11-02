package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"sentinelgo/internal/config"
	"sentinelgo/internal/osinfo/shared"
)

func fakeMDM(t *testing.T, info *shared.MDMInfo) *string {
	t.Helper()
	var gotHost string
	prevCollect, prevLoad := collectMDM, loadDefaultConfig
	t.Cleanup(func() { collectMDM, loadDefaultConfig = prevCollect, prevLoad })
	loadDefaultConfig = func() (*config.Config, error) { return &config.Config{MDMHost: "mdm.example.com"}, nil }
	collectMDM = func(host string) *shared.MDMInfo { gotHost = host; return info }
	return &gotHost
}

func TestRunMDM_Status(t *testing.T) {
	yes, no := true, false
	host := fakeMDM(t, &shared.MDMInfo{
		Enrolled: true, UserApproved: true, EnrollmentType: "profile", Supervised: &no,
		ServerURLHost: "mdm.example.com", IsOurServer: true, ADEAssigned: &no, BootstrapTokenEscrowed: nil,
		ManagedSettings: []string{"filevault", "firewall"}, Grants: shared.MDMGrants{FullDiskAccess: &yes},
		Identity: shared.MDMIdentity{Serial: "S1", ProvisioningUDID: "P1"},
	})
	var out, errOut bytes.Buffer
	if code := RunMDM([]string{"status"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if *host != "mdm.example.com" {
		t.Errorf("collector got host %q, want the config's mdm_host", *host)
	}
	for _, want := range []string{"Enrolled:          yes", "mdm.example.com (this deployment's MDM: yes)", "Bootstrap Token:   unknown",
		"Full Disk Access:  yes", "Managed settings:  filevault, firewall", "Provisioning UDID: P1", "Hardware UUID:     -"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}

	out.Reset()
	if code := RunMDM([]string{"status", "-json"}, &out, &errOut); code != 0 {
		t.Fatalf("json exit %d", code)
	}
	var back shared.MDMInfo
	if err := json.Unmarshal(out.Bytes(), &back); err != nil || back.Identity.ProvisioningUDID != "P1" {
		t.Errorf("json = %s (%v)", out.String(), err)
	}
}

func TestRunMDM_NoCollectorAndUsage(t *testing.T) {
	fakeMDM(t, nil)
	var out, errOut bytes.Buffer
	if code := RunMDM([]string{"status"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "isn't collected") {
		t.Errorf("exit %d, output %q", code, out.String())
	}
	if code := RunMDM(nil, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "usage") {
		t.Errorf("no subcommand: exit %d", code)
	}
}
