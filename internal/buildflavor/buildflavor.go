// Package buildflavor says which features this binary was built with (#547).
//
// The read-only build (`-tags readonly`) is a reporting agent: it collects and
// sends inventory but has no way to run code on the device or change it. The
// features it lacks are constants, not settings: a constant false makes the
// compiler drop the gated code, so no config value, server reply or task can
// turn it back on. Only a different build can.
//
// Gate a feature where it is registered or started (a native.Register in
// init, the executor's script path, MainIntegration wiring), not deep inside
// it, so the whole feature is unreachable and the linker leaves it out.
//
// A constant marked "for now" is meant to become a runtime toggle later:
// replace it with the config or server switch, nothing else has to move.
package buildflavor

// Flavor names.
const (
	FlavorFull     = "full"
	FlavorReadOnly = "readonly"
)

// ReadOnly reports whether this is the read-only build.
const ReadOnly = Flavor == FlavorReadOnly

// NotAvailable is the error text for a task or command the read-only build
// doesn't have.
const NotAvailable = "not available in this read-only build"

// Feature names, as the agent reports them in build_features and the server
// checks them (Compliance-OS#1076). A constant added later gets a new name;
// never rename one.
const (
	FeatureScripts        = "scripts"
	FeatureDeviceActions  = "device_actions"
	FeatureDLPEnforcement = "dlp_enforcement"
	FeatureYARA           = "yara"
	FeatureNotifyUser     = "notify_user"
	FeatureMDMEnroll      = "mdm_enroll"
)

// Features lists the features compiled into this build: all six in the full
// build, none in the read-only one. It is never nil, so the payload always
// carries the key (a missing key means an older, full agent). It means
// "compiled in": when a feature becomes a runtime toggle, the server owns the
// toggle and this list doesn't change.
func Features() []string {
	out := []string{}
	for _, f := range []struct {
		on   bool
		name string
	}{
		{Scripts, FeatureScripts},
		{DeviceActions, FeatureDeviceActions},
		{DLPEnforcement, FeatureDLPEnforcement},
		{YARA, FeatureYARA},
		{NotifyUser, FeatureNotifyUser},
		{MDMEnroll, FeatureMDMEnroll},
	} {
		if f.on {
			out = append(out, f.name)
		}
	}
	return out
}
