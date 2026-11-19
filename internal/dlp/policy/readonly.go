package policy

import "sentinelgo/internal/buildflavor"

// monitorOnly makes b report and never block, for a build without DLP
// enforcement (the read-only build, #547): every policy action becomes
// monitor, the files module is audit-only, and upload inspection, network
// controls and at-rest classification (which only serves taint blocks) are
// off. The full build leaves b as it is. It writes only what isn't so yet,
// so compiling an already decoded bundle changes nothing.
func monitorOnly(b *Bundle) {
	if buildflavor.DLPEnforcement {
		return
	}
	for i := range b.Policies {
		if a := b.Policies[i].Action; a != ActionMonitor && validAction(a) {
			b.Policies[i].Action = ActionMonitor
		}
	}
	f := &b.Modules.Files
	if f.AuditOnly == nil || !*f.AuditOnly {
		auditOnly := true
		f.AuditOnly = &auditOnly
	}
	if f.Uploads.Inspection.Enabled {
		f.Uploads.Inspection.Enabled = false
	}
	if f.NetworkControl.Enabled {
		f.NetworkControl.Enabled = false
	}
	if f.AtRest.Enabled {
		f.AtRest.Enabled = false
	}
}
