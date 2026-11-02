package clipboard

import (
	"crypto/sha256"
	"strings"
	"time"

	"sentinelgo/internal/dlp/detect"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
)

// Defaults for when the bundle has no message of its own.
const (
	defaultBlockMessage  = "Blocked by SentinelOps: {{detector}}"
	defaultNotifyMessage = "SentinelOps blocked sensitive data on your clipboard: {{detector}}"
	defaultWarnMessage   = "SentinelOps: you copied {{detector}}. This was allowed and logged."
	notifyTitle          = "SentinelOps DLP"
)

// Decision is what to do with one copy.
type Decision struct {
	Block   bool
	Warn    bool           // a policy warns and none blocks: keep the content, tell the user
	Message string         // the placeholder to put on the clipboard when Block
	Notify  string         // the desktop notification text when Block or Warn
	Events  []events.Event // one per matching policy
}

// Decide scans text against every clipboard policy in p. Policies whose
// exceptions list src are skipped. Every matching policy gets an event, and
// the strictest action wins: if any matching policy blocks, the copy is
// blocked; otherwise if any warns, the content stays and the user is told.
// The text itself never leaves this function except through events.Build
// (hash, length, and an excerpt in evidence_mode "full").
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
	var blockFinding, warnFinding *detect.Finding
	for _, pol := range pols {
		if excepted(pol.Exceptions.SourceApps, src) {
			continue
		}
		ok, used := p.Clipboard.Evaluate(pol.Match, pol.Rules, res)
		if !ok {
			continue
		}
		action := events.ActionMonitored
		switch pol.Action {
		case policy.ActionBlock:
			action = events.ActionBlocked
			d.Block = true
			if blockFinding == nil {
				blockFinding = &used[0]
			}
		case policy.ActionWarn:
			action = events.ActionWarned
			if warnFinding == nil {
				warnFinding = &used[0]
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
		d.Message = fillDetector(p.Modules.Clipboard.BlockMessage, defaultBlockMessage, blockFinding.DetectorID)
		d.Notify = fillDetector(p.Modules.Clipboard.NotifyMessage, defaultNotifyMessage, blockFinding.DetectorID)
	} else if warnFinding != nil {
		d.Warn = true
		d.Notify = fillDetector(p.Modules.Clipboard.WarnMessage, defaultWarnMessage, warnFinding.DetectorID)
	}
	return d
}

// fillDetector fills the {{detector}} placeholder of tmpl (def when empty)
// with a readable name.
func fillDetector(tmpl, def, detectorID string) string {
	if tmpl == "" {
		tmpl = def
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

// dedupeKey identifies a copy for "same as last time": the text and the app
// it came from (the same text from another app may be judged differently).
func dedupeKey(text string, src events.SourceApp) [32]byte {
	return sha256.Sum256([]byte(src.Path + "\x00" + src.Name + "\x00" + src.BundleID + "\x00" + text))
}

// markMonitored records events of a copy that couldn't be replaced as
// monitored: the content is still on the clipboard.
func markMonitored(evs []events.Event) {
	for i := range evs {
		evs[i].Action = events.ActionMonitored
	}
}

// excepted reports whether src matches one of the policy's exempted apps, by
// executable name (with or without .exe), full path or bundle id,
// case-insensitively.
func excepted(apps []string, src events.SourceApp) bool {
	if len(apps) == 0 {
		return false
	}
	// Case-insensitive, either path separator, with or without ".exe".
	norm := func(s string) string {
		return strings.TrimSuffix(strings.ReplaceAll(strings.ToLower(s), `\`, "/"), ".exe")
	}
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
