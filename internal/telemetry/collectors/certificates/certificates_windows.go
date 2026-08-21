//go:build windows

package certificates

import (
	"context"

	"sentinelgo/internal/osinfo/shared"
)

// certScript reads the two trust stores that matter for endpoint posture:
// Root (what this device trusts as a CA) and My (this device's own identity
// certificates). NotBefore/NotAfter are explicitly formatted with .ToString('o')
// (ISO 8601 round-trip) rather than left as .NET DateTime objects, which
// ConvertTo-Json would otherwise render as an ambiguous "/Date(ms)/" string —
// the same locale/format trap already avoided elsewhere in this codebase
// (quser, Win32_QuickFixEngineering.InstalledOn).
const certScript = `$stores = @(
	@{ Path = 'Cert:\LocalMachine\Root'; Name = 'root' },
	@{ Path = 'Cert:\LocalMachine\My'; Name = 'my' }
)
$stores | ForEach-Object {
	$storeName = $_.Name
	Get-ChildItem $_.Path -ErrorAction SilentlyContinue | ForEach-Object {
		[PSCustomObject]@{
			Subject = ''+$_.Subject
			Issuer = ''+$_.Issuer
			Thumbprint = ''+$_.Thumbprint
			NotBefore = $_.NotBefore.ToString('o')
			NotAfter = $_.NotAfter.ToString('o')
			Store = $storeName
		}
	}
} | ConvertTo-Json -Compress`

func platformCertificates(_ context.Context) signal {
	out, err := shared.RunCommand("powershell", "-NoProfile", "-Command", certScript)
	if err != nil {
		return signal{Warnings: []string{"certificate store query failed"}, Err: err}
	}

	rows, parseErr := parseWindowsCerts(out)
	if parseErr != nil {
		return signal{Warnings: []string{"certificate store query returned unparseable JSON"}, Err: parseErr}
	}

	certs := make([]Certificate, 0, len(rows))
	for _, r := range rows {
		certs = append(certs, r.toCertificate())
	}

	return signal{Certificates: certs, Source: "powershell:Cert:"}
}
