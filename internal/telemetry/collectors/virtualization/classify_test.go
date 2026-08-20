package virtualization

import "testing"

func TestClassifyVendor(t *testing.T) {
	tests := []struct {
		name           string
		manufacturer   string
		model          string
		wantHypervisor string
		wantCloud      string
		wantIsVirtual  bool
	}{
		// Physical hardware, including the specific case a real bug would have
		// broken: a corporate laptop with VBS/Credential Guard or the Hyper-V
		// role turned on. classifyVendor never sees HypervisorPresent at all
		// (virtualization_windows.go deliberately does not query it — see its
		// doc comment), so vendor/model strings unchanged by VBS being on must
		// still classify as physical.
		{"physical Windows, VBS/Hyper-V role enabled (Dell)", "Dell Inc.", "OptiPlex 7090", "", "", false},
		{"physical Windows, VBS/Hyper-V role enabled (HP)", "HP", "EliteBook 840 G8", "", "", false},
		{"physical Windows, VBS/Hyper-V role enabled (Lenovo)", "LENOVO", "ThinkPad X1 Carbon Gen 11", "", "", false},
		{"Microsoft-branded physical device, no VM model", "Microsoft Corporation", "Surface Laptop 5", "", "", false},

		{"VMware vendor field", "VMware, Inc.", "VMware7,1", "VMware", "", true},
		{"VMware via model only (macOS Fusion guest)", "", "VMware7,1", "VMware", "", true},

		{"Hyper-V guest", "Microsoft Corporation", "Virtual Machine", "Hyper-V", "", true},

		{"KVM", "QEMU", "Standard PC (i440FX + PIIX, 1996)", "QEMU/KVM", "", true},
		{"Proxmox VE guest (QEMU/KVM under the hood)", "QEMU", "pc-i440fx-8.1", "QEMU/KVM", "", true},

		{"VirtualBox", "innotek GmbH", "VirtualBox", "VirtualBox", "", true},

		{"AWS EC2 (Nitro)", "Amazon EC2", "", "", "aws", true},
		{"AWS EC2 (Xen-based, older instance types)", "Xen", "HVM domU", "Xen", "", true},

		// Azure VMs report the identical Manufacturer/Model pair as an on-prem
		// Hyper-V host: "Microsoft Corporation" / "Virtual Machine". The agent
		// makes no instance-metadata network call to disambiguate (see the
		// matrix doc and classifyVendor's own doc comment), so this must
		// classify as Hyper-V with cloud left empty rather than guessing
		// "azure" — do-not-fabricate over a confident-looking wrong answer.
		{"Azure VM (same signature as on-prem Hyper-V; not guessed)", "Microsoft Corporation", "Virtual Machine", "Hyper-V", "", true},

		{"GCP", "Google", "Google Compute Engine", "", "gcp", true},

		{"Xen (generic)", "Xen", "HVM domU", "Xen", "", true},
		{"QEMU (generic, non-KVM)", "QEMU", "Standard PC", "QEMU/KVM", "", true},
		{"Parallels", "Parallels Software International", "Parallels Virtual Platform", "Parallels", "", true},
		{"empty", "", "", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hv, cloud, isVirtual := classifyVendor(tc.manufacturer, tc.model)
			if hv != tc.wantHypervisor {
				t.Errorf("hypervisor = %q, want %q", hv, tc.wantHypervisor)
			}
			if cloud != tc.wantCloud {
				t.Errorf("cloud = %q, want %q", cloud, tc.wantCloud)
			}
			if isVirtual != tc.wantIsVirtual {
				t.Errorf("isVirtual = %v, want %v", isVirtual, tc.wantIsVirtual)
			}
		})
	}
}

func TestMapSystemdVirt(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantHV   string
		wantVirt bool
	}{
		{"bare metal", "none", "", false},
		{"empty (tool absent/failed upstream)", "", "", false},
		{"KVM", "kvm", "KVM", true},
		{"Proxmox VE guest (systemd reports kvm)", "kvm", "KVM", true},
		{"QEMU (software emulation, no hw accel)", "qemu", "QEMU", true},
		{"VMware", "vmware", "VMware", true},
		{"Hyper-V guest", "microsoft", "Hyper-V", true},
		{"Xen", "xen", "Xen", true},
		{"VirtualBox (systemd reports oracle)", "oracle", "VirtualBox", true},
		{"Parallels", "parallels", "Parallels", true},
		{"whitespace/case tolerance", "  KVM\n", "KVM", true},
		{"unrecognised value still reported, not discarded", "bhyve", "bhyve", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hv, isVirt := mapSystemdVirt(tc.input)
			if hv != tc.wantHV || isVirt != tc.wantVirt {
				t.Errorf("mapSystemdVirt(%q) = (%q, %v), want (%q, %v)", tc.input, hv, isVirt, tc.wantHV, tc.wantVirt)
			}
		})
	}
}
