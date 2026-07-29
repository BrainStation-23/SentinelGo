package epm

import (
	"encoding/json"
	"time"
)

// PolicyBundle is the signed, versioned unit of policy distribution — the
// Phase 3 wire/storage shape a backend ships instead of (or in addition to)
// the v1 epm-policy-sync task payload. See BundleManager.Apply for how a
// bundle actually becomes live policy, and adapter_v1.go/UpgradeV1 for how
// the OLDER v1 PolicyRule shape continues to work side by side with this —
// nothing about Phase 3 requires a backend to adopt bundles at all.
type PolicyBundle struct {
	SchemaVersion int       `json:"schema_version"` // bundle FORMAT version (=2, matching RuleV2's condition-tree model)
	BundleID      string    `json:"bundle_id"`
	Generation    int64     `json:"generation"`          // monotonic per tenant
	ParentID      string    `json:"parent_id,omitempty"` // delta only: the bundle this patches
	TenantID      string    `json:"tenant_id"`
	Mode          string    `json:"mode"` // "full" | "delta"
	IssuedAt      time.Time `json:"issued_at"`
	NotAfter      time.Time `json:"not_after,omitempty"` // staleness bound; zero = no bound

	Rules      []RuleV2    `json:"rules,omitempty"`
	RuleGroups []RuleGroup `json:"rule_groups,omitempty"`
	RemovedIDs []string    `json:"removed_ids,omitempty"` // delta only
	Defaults   Defaults    `json:"defaults"`
}

// Defaults carries tenant-wide settings the compiled rule set and the
// context engine (Phase 4) both draw from: TimeDefaults feeds
// CondBusinessHours/CondDayOfWeek directly (see CompiledRuleSet.Defaults);
// the network/org fields feed Phase 4's devicectx corporate-network and
// device-group/org/department classification, which is why they are
// declared here rather than duplicated — a bundle is the one place an
// operator actually configures them.
type Defaults struct {
	TimeDefaults

	DefaultVerdict Verdict `json:"default_verdict,omitempty"` // "" => deny (unchanged default)

	CorporateDNSSuffixes []string `json:"corporate_dns_suffixes,omitempty"`
	CorporateCIDRs       []string `json:"corporate_cidrs,omitempty"`
	CorporateGatewayMACs []string `json:"corporate_gateway_macs,omitempty"`
	VPNAdapterPatterns   []string `json:"vpn_adapter_patterns,omitempty"`

	DeviceGroups []string `json:"device_groups,omitempty"`
	Org          string   `json:"org,omitempty"`
	Department   string   `json:"department,omitempty"`

	// Canaries are (request, expected verdict) pairs shipped inside the
	// bundle itself, evaluated against the newly-compiled rule set before
	// activation — see BundleManager.Apply. A bundle whose own canaries
	// don't pass is rejected: a default-deny system that silently accepts a
	// broken bundle locks every user out of every elevation.
	Canaries []Canary `json:"canaries,omitempty"`
}

// Canary is one compile-time self-check a bundle carries.
type Canary struct {
	Name     string             `json:"name"`
	Request  ElevationRequestV2 `json:"request"`
	Context  ContextSnapshot    `json:"context,omitempty"`
	Expected Verdict            `json:"expected"`
}

// SignedBundle wraps a PolicyBundle's canonical bytes with a detached
// ed25519 signature, mirroring internal/updater's release-binary signing
// (verifySignatureBytes + PublicKey) and scripts/sign exactly. Payload is
// signed and verified as the RAW BYTES RECEIVED, never a re-marshalled
// struct — see VerifyBundle — which sidesteps canonical-JSON entirely, the
// same way downloadAndVerify signs the actual binary bytes rather than some
// derived representation of them.
type SignedBundle struct {
	Payload   json.RawMessage `json:"payload"`
	Algorithm string          `json:"alg"` // "ed25519"
	KeyID     string          `json:"key_id"`
	Signature string          `json:"sig"` // base64
}

// DecodePayload unmarshals sb.Payload into a PolicyBundle. Separate from
// verification (VerifyBundle) so a caller can decode first (to log which
// bundle failed verification) and verify second, or vice versa, without
// re-parsing.
func (sb *SignedBundle) DecodePayload() (*PolicyBundle, error) {
	var b PolicyBundle
	if err := json.Unmarshal(sb.Payload, &b); err != nil {
		return nil, err
	}
	return &b, nil
}
