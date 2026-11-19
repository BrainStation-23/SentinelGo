package policy

import "sentinelgo/internal/buildflavor"

// monitorOnly returns the bundle a build without DLP enforcement (the
// read-only build, #547) applies: every policy action becomes monitor, the
// files module is audit-only, and upload inspection, network controls and
// at-rest classification (which only serves taint blocks) are off. The full
// build gets b itself.
//
// Only Compile applies it, to a copy: the decoded bundle, which the policy
// cache saves, keeps the server's actions, so a device switched back to the
// full build blocks again at once.
func monitorOnly(b *Bundle) *Bundle {
	if buildflavor.DLPEnforcement {
		return b
	}
	return forceMonitor(b)
}

// forceMonitor is monitorOnly's rewrite, whatever the build. It leaves b
// alone and returns a changed copy.
func forceMonitor(b *Bundle) *Bundle {
	c := *b
	c.Policies = append([]Policy(nil), b.Policies...)
	for i := range c.Policies {
		if validAction(c.Policies[i].Action) {
			c.Policies[i].Action = ActionMonitor
		}
	}
	auditOnly := true
	f := &c.Modules.Files
	f.AuditOnly = &auditOnly
	f.Uploads.Inspection.Enabled = false
	f.NetworkControl.Enabled = false
	f.AtRest.Enabled = false
	return &c
}
