//go:build !readonly

package buildflavor

// Flavor is the build this binary is: "full" or "readonly".
const Flavor = FlavorFull

// Features. See flavor_readonly.go for what each one gates.
const (
	Scripts        = true
	DeviceActions  = true
	DLPEnforcement = true
	YARA           = true
	NotifyUser     = true
	MDMEnroll      = true
)
