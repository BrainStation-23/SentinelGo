package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"runtime"
	"strings"

	"sentinelgo/internal/config"
	"sentinelgo/internal/osinfo/mdm"
	"sentinelgo/internal/osinfo/shared"
)

// MDMCommand is `sentinelgo mdm status`: the device's MDM state as the
// inventory reports it, for support.
const MDMCommand = "mdm"

// collectMDM is mdm.Collect; a var for tests.
var collectMDM = mdm.Collect

// RunMDM runs `sentinelgo mdm status [-json] [-config PATH]` and returns the
// exit code.
func RunMDM(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "status" {
		_, _ = fmt.Fprintln(stderr, "usage: sentinelgo mdm status [-json] [-config PATH]")
		return 2
	}
	fs := flag.NewFlagSet("mdm status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "config.json of the install to inspect (default: the standard path)")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	load := loadDefaultConfig
	if *cfgPath != "" {
		load = func() (*config.Config, error) { return config.Load(*cfgPath) }
	}
	ourHost := ""
	if cfg, err := load(); err == nil {
		ourHost = cfg.MDMHost
	}

	info := collectMDM(ourHost)
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(info); err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	printMDM(stdout, info)
	return 0
}

func printMDM(w io.Writer, info *shared.MDMInfo) {
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format+"\n", a...) }
	if info == nil {
		p("MDM state isn't collected on %s yet.", runtime.GOOS)
		return
	}
	if info.Eligible != nil {
		eligible := yesNo(*info.Eligible)
		if info.IneligibleReason != "" {
			eligible += " (" + info.IneligibleReason + ")"
		}
		p("Edition:           %s", orDash(info.Edition))
		p("MDM eligible:      %s", eligible)
	}
	p("Enrolled:          %s", yesNo(info.Enrolled))
	if info.Enrolled {
		p("  type:            %s", info.EnrollmentType)
		if info.Eligible == nil { // user approval is an Apple concept
			p("  user approved:   %s", yesNo(info.UserApproved))
		}
		p("  server:          %s (this deployment's MDM: %s)", orDash(info.ServerURLHost), yesNo(info.IsOurServer))
	}
	if info.OtherMDM != "" {
		p("Other MDM:         %s", info.OtherMDM)
	}
	for _, e := range info.Enrollments {
		p("  enrollment %s: %s, %s, %s", e.ID, orDash(e.ServerHost), e.Type, e.State)
	}
	if info.Eligible != nil { // Windows: the Apple-only fields below don't apply
		p("Managed settings:  %s", orDash(strings.Join(info.ManagedSettings, ", ")))
		p("OMA-DM device ID:  %s", orDash(info.Identity.OMADMDeviceID))
		p("SMBIOS UUID:       %s", orDash(info.Identity.SMBIOSUUID))
		return
	}
	p("Supervised:        %s", tri(info.Supervised))
	ade := tri(info.ADEAssigned)
	if info.ADEServerHost != "" {
		ade += " (" + info.ADEServerHost + ")"
	}
	p("ADE assigned:      %s", ade)
	p("Bootstrap Token:   %s", tri(info.BootstrapTokenEscrowed))
	p("Full Disk Access:  %s", tri(info.Grants.FullDiskAccess))
	p("Managed settings:  %s", orDash(strings.Join(info.ManagedSettings, ", ")))
	p("Serial:            %s", orDash(info.Identity.Serial))
	p("Provisioning UDID: %s", orDash(info.Identity.ProvisioningUDID))
	p("Hardware UUID:     %s", orDash(info.Identity.HardwareUUID))
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// tri prints a value the agent may not have been able to determine.
func tri(b *bool) string {
	if b == nil {
		return "unknown"
	}
	return yesNo(*b)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
