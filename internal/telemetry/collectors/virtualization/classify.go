package virtualization

import "strings"

// classifyVendor inspects a manufacturer/model pair and reports the
// hypervisor and cloud platform they imply, per
// docs/telemetry/03-collection-matrix.md.
//
// No build tag: this is pure string matching, exercised the same way from a
// Windows WMI query, a Linux DMI sysfs read, or a macOS hw.model string, so it
// is unit tested on every host regardless of which platform file runs.
//
// The agent never queries a cloud instance-metadata endpoint to disambiguate
// further (that is an outbound network call from every endpoint, per the
// matrix doc) — cloud_platform is therefore left empty whenever a vendor
// string is genuinely ambiguous, such as generic "Microsoft
// Corporation"/"Virtual Machine" (on-prem Hyper-V and Azure both report this).
func classifyVendor(manufacturer, model string) (hypervisor, cloud string, isVirtual bool) {
	// A single combined haystack rather than separately-checked fields: which
	// field carries the tell varies by platform. Windows puts "VMware, Inc."
	// in Manufacturer; a macOS VMware Fusion guest puts "VMware7,1" in
	// hw.model, with no separate manufacturer field at all.
	h := strings.ToLower(manufacturer + " " + model)

	switch {
	case strings.Contains(h, "amazon"):
		return "", "aws", true
	case strings.Contains(h, "google"):
		return "", "gcp", true
	case strings.Contains(h, "vmware"):
		return "VMware", "", true
	case strings.Contains(h, "virtualbox") || strings.Contains(h, "innotek"):
		return "VirtualBox", "", true
	case strings.Contains(h, "parallels"):
		return "Parallels", "", true
	case strings.Contains(h, "xen"):
		return "Xen", "", true
	case strings.Contains(h, "qemu"):
		return "QEMU/KVM", "", true
	case strings.Contains(h, "microsoft corporation") && strings.Contains(h, "virtual machine"):
		return "Hyper-V", "", true
	default:
		return "", "", false
	}
}

// mapSystemdVirt maps a `systemd-detect-virt --vm` value to a hypervisor
// name. "none" and "" (the tool reports "none" and exits non-zero when the
// host is not virtualized) both mean bare metal.
//
// An unrecognised non-empty value is still reported as-is rather than
// discarded: systemd's virtualization list grows over time, and surfacing the
// raw value beats silently losing "this host is virtual" information.
func mapSystemdVirt(v string) (hypervisor string, isVirtual bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "", "none":
		return "", false
	case "kvm":
		return "KVM", true
	case "qemu":
		return "QEMU", true
	case "vmware":
		return "VMware", true
	case "microsoft":
		return "Hyper-V", true
	case "xen":
		return "Xen", true
	case "oracle":
		return "VirtualBox", true
	case "parallels":
		return "Parallels", true
	default:
		return v, true
	}
}
