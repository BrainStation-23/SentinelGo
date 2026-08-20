// Package virtualization implements the telemetry VM/Hypervisor Detection
// collector, filling the "virtualization" section: whether the endpoint is a
// virtual machine, which hypervisor it runs under (when determinable from
// vendor/model strings), and which cloud platform (when determinable the same
// way — never via an instance-metadata network call).
package virtualization

import (
	"context"

	tel "sentinelgo/internal/telemetry"
)

// Name is the collector's identifier, also used as its section name.
const Name = tel.SectionVirtualization

// Payload is the wire shape of the "virtualization" section.
type Payload struct {
	IsVirtual bool `json:"is_virtual"`
	// Hypervisor names the mechanism when it could be determined from
	// vendor/model strings or a virt-detection tool, e.g. "VMware", "Hyper-V",
	// "KVM", "VirtualBox", "Xen", "Parallels". Empty when the host is virtual
	// but the specific hypervisor could not be identified, or when the host is
	// physical.
	Hypervisor string `json:"hypervisor,omitempty"`
	// CloudPlatform is "aws", "gcp" or empty. Detected from DMI vendor strings
	// only; the agent never queries a cloud metadata endpoint.
	CloudPlatform string `json:"cloud_platform,omitempty"`
}

// signal is what platform code supplies before classification.
type signal struct {
	Manufacturer string
	Model        string
	// HintVirtual is a platform-native "is this a VM" answer (Windows'
	// HypervisorPresent, macOS's kern.hv_vmm_present, or a recognised
	// systemd-detect-virt result) used when vendor/model strings alone are
	// ambiguous or absent.
	HintVirtual    bool
	HintHypervisor string
	Source         string
	Warnings       []string
}

// Collector implements telemetry.Collector for VM/hypervisor detection.
type Collector struct{}

// New returns the VM/Hypervisor Detection collector.
func New() *Collector { return &Collector{} }

func (c *Collector) Name() string       { return Name }
func (c *Collector) Section() string    { return tel.SectionVirtualization }
func (c *Collector) SchemaVersion() int { return 1 }

// Capability reports whether this host offers any detection mechanism at all.
// Bare metal is a legitimate CapSupported result (is_virtual=false); the
// unsupported case is reserved for hosts with no usable mechanism — see
// platformCapability in each platform file.
func (c *Collector) Capability(ctx context.Context, _ tel.CollectorConfig) (string, tel.CapabilityState) {
	return tel.CapKeyVirtualization, platformCapability(ctx)
}

// Collect classifies the host as physical or virtual.
func (c *Collector) Collect(ctx context.Context, _ tel.CollectorConfig) (any, tel.CollectorResult) {
	res, done := tel.NewResult(c.Name(), c.Section())

	sig := platformSignal(ctx)
	for _, w := range sig.Warnings {
		res.AddWarning(w)
	}

	hypervisor, cloud, isVirtual := classifyVendor(sig.Manufacturer, sig.Model)
	if !isVirtual && sig.HintVirtual {
		isVirtual = true
		if hypervisor == "" {
			hypervisor = sig.HintHypervisor
		}
	}

	payload := Payload{
		IsVirtual:     isVirtual,
		Hypervisor:    hypervisor,
		CloudPlatform: cloud,
	}

	return payload, *done(nil, sig.Source, 1)
}
