//go:build windows

package patches

import (
	"context"
	"strings"
	"time"

	"github.com/yusufpapurcu/wmi"

	"sentinelgo/internal/osinfo/shared"
)

type win32QuickFixEngineering struct {
	HotFixID    string
	Description string
	InstalledOn string
}

// pendingSearchTimeout bounds the Windows Update COM search independently of
// the caller's context. Collectors in one telemetry cycle share a single
// context with no per-collector deadline (see RunAll in collector.go), so an
// unbounded Windows Update search — which can legitimately take well over a
// minute, confirmed by hand against a real host — would delay every other
// collector in the same cycle, not just this one. Patches collects every 6h
// per section.go, so missing a search this cycle and getting it next time is
// a fair trade against blocking the whole cycle.
const pendingSearchTimeout = 25 * time.Second

// pendingUpdateScript searches Windows Update for not-installed, not-hidden
// updates via the COM API — the mechanism the matrix doc recommends because
// WQL/WMI has no equivalent query surface for "what's pending".
//
// $ErrorActionPreference = 'Stop' plus try/catch is load-bearing, the same
// reason as the BitLocker script in the encryption collector: a non-admin
// caller or a WU service in a bad state can fail with a non-terminating
// error that would otherwise leave stdout empty and exit code 0, silently
// reporting "success, nothing pending" instead of a genuine failure.
const pendingUpdateScript = `$ErrorActionPreference = 'Stop'
try {
	$session = New-Object -ComObject Microsoft.Update.Session
	$searcher = $session.CreateUpdateSearcher()
	$result = $searcher.Search("IsInstalled=0 and IsHidden=0")
	$result.Updates | ForEach-Object {
		$kb = if ($_.KBArticleIDs.Count -gt 0) { 'KB' + $_.KBArticleIDs[0] } else { '' }
		$cat = if ($_.Type -eq 2) { 'driver' } else { 'quality' }
		[PSCustomObject]@{ ID = $kb; Description = ''+$_.Title; Category = $cat }
	} | ConvertTo-Json -Compress -Depth 4
} catch {
	exit 1
}`

func platformUpdates(ctx context.Context) signal {
	var updates []Update
	var warnings []string
	var sources []string

	if installed, err := readInstalled(); err == nil {
		updates = append(updates, installed...)
		sources = append(sources, "wmi:Win32_QuickFixEngineering")
	} else {
		warnings = append(warnings, "Win32_QuickFixEngineering query failed")
	}

	searchCtx, cancel := context.WithTimeout(ctx, pendingSearchTimeout)
	defer cancel()
	if pending, err := readPending(searchCtx); err == nil {
		updates = append(updates, pending...)
		sources = append(sources, "com:Microsoft.Update.Session")
	} else {
		warnings = append(warnings, "Windows Update pending search failed or timed out")
	}

	return signal{Updates: updates, Source: strings.Join(sources, ", "), Warnings: warnings}
}

func readInstalled() ([]Update, error) {
	var rows []win32QuickFixEngineering
	if err := wmi.Query("SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering", &rows); err != nil {
		return nil, err
	}
	updates := make([]Update, 0, len(rows))
	for _, r := range rows {
		updates = append(updates, Update{
			ID:          r.HotFixID,
			Description: r.Description,
			Category:    "quality",
			Status:      "installed",
			// InstalledOn is passed through as-is: Win32_QuickFixEngineering
			// reports it as a locale-formatted string, not a CIM datetime,
			// the same locale trap already avoided for quser/who.
			InstalledOn: r.InstalledOn,
		})
	}
	return updates, nil
}

func readPending(ctx context.Context) ([]Update, error) {
	out, err := shared.RunCommandContext(ctx, "powershell", "-NoProfile", "-Command", pendingUpdateScript)
	if err != nil {
		return nil, err
	}
	rows, err := parseWindowsPending(out)
	if err != nil {
		return nil, err
	}
	updates := make([]Update, 0, len(rows))
	for _, r := range rows {
		updates = append(updates, Update{
			ID:          r.ID,
			Description: r.Description,
			Category:    r.Category,
			Status:      "pending",
		})
	}
	return updates, nil
}
