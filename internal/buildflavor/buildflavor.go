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
