package clipboard

import (
	"strings"
	"time"

	"sentinelgo/internal/dlp/detect"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
)

// defaultBlockMessage is used when the bundle has none.
const defaultBlockMessage = "Blocked by SentinelOps: {{detector}}"

// Decision is what to do with one copy.
type Decision struct {
	Block   bool
	Message string         // the placeholder to put on the clipboard when Block
	Events  []events.Event // one per matching policy
}

// Decide scans text against every clipboard policy in p. Policies whose
// exceptions list src are skipped. If any matching policy blocks, the copy is
// blocked; every matching policy gets an event. The text itself never leaves
// this function except through events.Build (hash, length, and an excerpt in
// evidence_mode "full").
func Decide(p *policy.Compiled, text string, src events.SourceApp, now time.Time) Decision {
	var d Decision
	if p == nil || p.Clipboard == nil || text == "" {
		return d
	}
	pols := p.For(Name)
	if len(pols) == 0 {
		return d
	}
	res := p.Clipboard.Scan(text)
	if len(res.Findings) == 0 {
		return d
	}
	var blockFinding *detect.Finding
	for _, pol := range pols {
		if excepted(pol.Exceptions.SourceApps, src) {
			continue
		}
		ok, used := p.Clipboard.Evaluate(pol.Match, pol.Rules, res)
		if !ok {
			continue
		}
		action := events.ActionMonitored
		if pol.Action == policy.ActionBlock {
			action = events.ActionBlocked
			d.Block = true
			if blockFinding == nil {
				blockFinding = &used[0]
			}
		}
		d.Events = append(d.Events, events.Build(
			events.Meta{Channel: Name, SourceApp: src, OccurredAt: now},
			events.Match{PolicyID: pol.ID, PolicyVersion: p.Version, Action: action, Severity: pol.Severity, EvidenceMode: p.EvidenceMode},
			res, used, text,
		))
	}
	if d.Block {
		// Every event of a blocked copy records the block: the content is gone.
		for i := range d.Events {
			d.Events[i].Action = events.ActionBlocked
		}
		d.Message = blockMessage(p.Modules.Clipboard.BlockMessage, blockFinding.DetectorID)
	}
	return d
}

// blockMessage fills the {{detector}} placeholder with a readable name.
func blockMessage(tmpl, detectorID string) string {
	if tmpl == "" {
		tmpl = defaultBlockMessage
	}
	return strings.ReplaceAll(tmpl, "{{detector}}", DetectorName(detectorID))
}

// DetectorName turns a detector id into a short label: "secrets.aws-access-token"
// becomes "aws access token", "pii.credit_card" becomes "credit card".
func DetectorName(id string) string {
	name := id
	if i := strings.IndexByte(id, '.'); i >= 0 {
		name = id[i+1:]
	}
	name = strings.NewReplacer("-", " ", "_", " ").Replace(name)
	if strings.HasPrefix(id, "custom.") {
		return "restricted content"
	}
	return name
}

// excepted reports whether src matches one of the policy's exempted apps, by
// executable name (with or without .exe), full path or bundle id,
// case-insensitively.
func excepted(apps []string, src events.SourceApp) bool {
	if len(apps) == 0 {
		return false
	}
	norm := func(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".exe") }
	candidates := []string{norm(src.Name), norm(src.Path), norm(src.BundleID)}
	if i := strings.LastIndexAny(src.Path, `/\`); i >= 0 {
		candidates = append(candidates, norm(src.Path[i+1:])) // either separator, whatever the OS
	}
	for _, a := range apps {
		for _, c := range candidates {
			if c != "" && c == norm(a) {
				return true
			}
		}
	}
	return false
}
