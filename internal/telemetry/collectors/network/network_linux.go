//go:build linux

package network

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// platformExtra reads MTU and physical/virtual state from sysfs (universal
// on Linux, no subprocess needed), DHCP state from NetworkManager when
// present (best-effort — a non-NetworkManager host, e.g. systemd-networkd or
// plain ifupdown, reports nil/undetermined rather than a guess), and proxy
// configuration from the standard http_proxy/https_proxy environment
// variables.
func platformExtra(ctx context.Context, names []string) signal {
	extra := make(map[string]extraFields, len(names))
	hasNmcli := false
	if _, err := exec.LookPath("nmcli"); err == nil {
		hasNmcli = true
	}

	for _, name := range names {
		e := extraFields{IsVPN: isVPNInterfaceName(name)}

		if mtu, err := shared.ReadFileContent("/sys/class/net/" + name + "/mtu"); err == nil {
			if n, convErr := strconv.Atoi(strings.TrimSpace(mtu)); convErr == nil {
				e.MTU = n
			}
		}

		if _, err := os.Lstat("/sys/class/net/" + name + "/device"); err == nil {
			physical := true
			e.IsPhysical = &physical
		} else if os.IsNotExist(err) {
			physical := false
			e.IsPhysical = &physical
		}

		if hasNmcli {
			out, _, cmdErr := shared.RunCommandOutputContext(ctx, "nmcli", "-g", "IP4.DHCP4", "device", "show", name)
			if cmdErr == nil {
				e.DHCPEnabled = parseNmcliDHCP(out)
			}
		}

		extra[name] = e
	}

	sig := signal{Extra: extra, Source: "sysfs:/sys/class/net"}
	if hasNmcli {
		sig.Source += ", exec:nmcli"
	}

	enabled, server := linuxProxyFromEnv()
	sig.ProxyEnabled = &enabled
	sig.ProxyServer = server

	return sig
}

// linuxProxyFromEnv reads the standard proxy environment variables. Set on
// this agent process's own environment — see the package doc's disclosed
// per-account limitation, the same caveat as the Windows/macOS mechanisms.
func linuxProxyFromEnv() (enabled bool, server string) {
	for _, key := range []string{"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return true, v
		}
	}
	return false, ""
}
