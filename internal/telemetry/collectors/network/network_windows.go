//go:build windows

package network

import (
	"context"
	"strings"

	"golang.org/x/sys/windows/registry"

	"sentinelgo/internal/osinfo/shared"
)

// ifaceScript joins Get-NetAdapter (Virtual) with Get-NetIPInterface (Dhcp,
// NlMtu) by name — the matrix doc's "adapter type from Get-NetAdapter"
// mechanism, extended to also read the IP-layer properties neither cmdlet
// exposes alone.
const ifaceScript = `$adapters = Get-NetAdapter | Select-Object Name,Virtual
$ipifaces = Get-NetIPInterface -AddressFamily IPv4 | Select-Object InterfaceAlias,Dhcp,NlMtu
$adapters | ForEach-Object {
	$a = $_
	$ip = $ipifaces | Where-Object { $_.InterfaceAlias -eq $a.Name } | Select-Object -First 1
	[PSCustomObject]@{
		Name = ''+$a.Name
		Mtu = if ($ip) { $ip.NlMtu } else { 0 }
		Dhcp = if ($ip) { ''+$ip.Dhcp } else { '' }
		Virtual = [bool]$a.Virtual
	}
} | ConvertTo-Json -Compress`

func platformExtra(_ context.Context, _ []string) signal {
	out, err := shared.RunCommand("powershell", "-NoProfile", "-Command", ifaceScript)
	if err != nil {
		return signal{Warnings: []string{"Get-NetAdapter/Get-NetIPInterface query failed"}, Err: err}
	}

	rows, parseErr := parseWindowsInterfaces(out)
	if parseErr != nil {
		return signal{Warnings: []string{"interface query returned unparseable JSON"}, Err: parseErr}
	}

	extra := make(map[string]extraFields, len(rows))
	for _, r := range rows {
		extra[r.Name] = r.toExtra()
	}

	// A "+"-joined single token here would be long enough (and drawn entirely
	// from the token/key character class) to trip SanitizeMessage's
	// secret-shaped-token redaction, turning this harmless diagnostic string
	// into "<redacted>" in every log and CollectorResult. ", " keeps the two
	// cmdlet names as separate, sub-32-character tokens.
	sig := signal{Extra: extra, Source: "powershell:Get-NetAdapter, Get-NetIPInterface"}

	if enabled, server, err := readWindowsProxy(); err == nil {
		sig.ProxyEnabled = &enabled
		sig.ProxyServer = server
	} else {
		sig.Warnings = append(sig.Warnings, "proxy registry read failed")
	}

	return sig
}

// readWindowsProxy reads the current process's own (service account's)
// Internet Settings — see the package doc's disclosed per-account
// limitation.
func readWindowsProxy() (enabled bool, server string, err error) {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return false, "", err
	}
	defer k.Close()

	v, _, err := k.GetIntegerValue("ProxyEnable")
	if err != nil {
		return false, "", err
	}
	enabled = v != 0

	if enabled {
		s, _, sErr := k.GetStringValue("ProxyServer")
		if sErr == nil {
			server = strings.TrimSpace(s)
		}
	}
	return enabled, server, nil
}
