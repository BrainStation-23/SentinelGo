//go:build readonly

package buildflavor

// Flavor is the build this binary is: "full" or "readonly".
const Flavor = FlavorReadOnly

// Features, all off in the read-only build.
const (
	// Scripts gates the script executor: console scripts, inline bodies and
	// task artifacts. Permanent.
	Scripts = false
	// DeviceActions gates the native tasks that change the device:
	// device-reboot, firewall-enable/-disable, local-admin-add/-remove,
	// admin-password-rotate, mdm-unenroll and mdm-sync. Permanent.
	DeviceActions = false
	// DLPEnforcement gates DLP blocking: block, warn and override actions,
	// the override prompt, the upload proxy and network controls. Detection
	// and events stay; every match is reported as monitored. Permanent.
	DLPEnforcement = false
	// YARA gates threat hunting: ruleset sync, scans, yara-scan/-cancel and
	// on-write scans. Off for now, to become a runtime toggle.
	YARA = false
	// NotifyUser gates the notify-user task. Off for now, to become a toggle.
	NotifyUser = false
	// MDMEnroll gates mdm-enroll and the Enroll now offer (#545). Off for
	// now, to become a toggle.
	MDMEnroll = false
)
