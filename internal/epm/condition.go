package epm

// ConditionKind identifies what fact a leaf Condition compares. Comparison
// itself (eq/glob/in/regex/version/between) lives once, in applyOperator
// (compile.go); a ConditionKind only has to supply a Matcher that knows how to
// pull comparable string values out of an EvalInput. See matchers.go.
type ConditionKind string

const (
	// Application identity.
	CondPath         ConditionKind = "path"
	CondFileName     ConditionKind = "file_name"
	CondSHA256       ConditionKind = "sha256"
	CondSHA1         ConditionKind = "sha1"
	CondScriptSHA256 ConditionKind = "script_sha256"
	CondPublisher    ConditionKind = "publisher"
	CondSigned       ConditionKind = "signed"
	// CondProductName, CondMSIProductCode, CondBundleID, and CondPackageName
	// read installer/package metadata (PE version resource, MSI product code,
	// macOS bundle identifier, dpkg/rpm package name respectively) that no
	// collector in this repository populates yet — see
	// ElevationRequestV2.ProductName etc. in matchers.go. They are wired into
	// the registry now, matching Unknown until a later phase's collector fills
	// the corresponding request field, so no engine change will be needed when
	// that collector lands.
	CondProductName    ConditionKind = "product_name"
	CondMSIProductCode ConditionKind = "msi_product_code"
	CondBundleID       ConditionKind = "bundle_id"
	CondPackageName    ConditionKind = "package_name"

	// Invocation.
	CondCommandLine   ConditionKind = "command_line"
	CondArgs          ConditionKind = "args"
	CondServiceName   ConditionKind = "service_name"
	CondParentProcess ConditionKind = "parent_process"
	CondChildProcess  ConditionKind = "child_process"

	// Principal.
	CondUser      ConditionKind = "user"
	CondUserSID   ConditionKind = "user_sid"
	CondUserGroup ConditionKind = "user_group"

	// Directory / organization.
	CondDeviceGroup  ConditionKind = "device_group"
	CondOrg          ConditionKind = "org"
	CondDepartment   ConditionKind = "department"
	CondDomainJoined ConditionKind = "domain_joined"
	CondEntraJoined  ConditionKind = "entra_joined"

	// Device posture (Phase 4 devicectx; Unknown until that provider is wired).
	CondDiskEncryption ConditionKind = "disk_encryption" // BitLocker/FileVault/LUKS
	CondSecureBoot     ConditionKind = "secure_boot"
	CondFirewall       ConditionKind = "firewall"
	CondAntivirus      ConditionKind = "antivirus"
	CondCompliance     ConditionKind = "compliance"

	// Network (Phase 4 devicectx).
	CondNetworkType      ConditionKind = "network_type"
	CondVPNActive        ConditionKind = "vpn_active"
	CondCorporateNetwork ConditionKind = "corporate_network"

	// Time. Computed inline from EvalInput.Now; never Unknown once a
	// BusinessHours definition exists (see EvalInput.Defaults), and simply
	// unmatched — not Unknown — when no definition is configured, since "no
	// business-hours policy configured" is a fact, not a missing one.
	CondBusinessHours ConditionKind = "business_hours"
	CondDayOfWeek     ConditionKind = "day_of_week"

	// Platform. CondOSType is always known (runtime.GOOS); CondOSVersion
	// depends on the device-posture snapshot like the rest of Phase 4.
	CondOSType    ConditionKind = "os_type"
	CondOSVersion ConditionKind = "os_version"
)

// Operator is the comparison a leaf Condition applies between a matcher's
// extracted value(s) and Condition.Value/Values.
type Operator string

const (
	OpEquals     Operator = "eq"
	OpIn         Operator = "in"
	OpGlob       Operator = "glob"
	OpPrefix     Operator = "prefix"
	OpSuffix     Operator = "suffix"
	OpContains   Operator = "contains"
	OpRegex      Operator = "regex" // RE2 only (regexp package) — no backtracking, no ReDoS
	OpVersionGTE Operator = "version_gte"
	OpVersionLT  Operator = "version_lt"
	OpBetween    Operator = "between" // Values[0]..Values[1], lexical or "HH:MM" for time kinds
	OpIsTrue     Operator = "is_true"
	OpIsFalse    Operator = "is_false"
)

// Valid reports whether op is a recognised operator.
func (op Operator) Valid() bool {
	switch op {
	case OpEquals, OpIn, OpGlob, OpPrefix, OpSuffix, OpContains, OpRegex,
		OpVersionGTE, OpVersionLT, OpBetween, OpIsTrue, OpIsFalse:
		return true
	}
	return false
}

// LogicOp combines child Conditions in a branch node.
type LogicOp string

const (
	LogicAnd LogicOp = "and"
	LogicOr  LogicOp = "or"
	LogicNot LogicOp = "not"
)

// Valid reports whether op is a recognised logic operator.
func (op LogicOp) Valid() bool {
	switch op {
	case LogicAnd, LogicOr, LogicNot:
		return true
	}
	return false
}

// Condition is one node of a rule's match tree. A node is either a LEAF
// (Kind/Operator/Value(s) set, Children empty) or a BRANCH (Logic set,
// Children non-empty); a node setting both, or neither, is a Compile error.
// A nil *Condition, or the zero value, means "wildcard" — matches
// unconditionally, exactly like a v1 PolicyRule with no application-identity
// field set.
type Condition struct {
	Kind     ConditionKind `json:"kind,omitempty"`
	Operator Operator      `json:"op,omitempty"`
	Value    string        `json:"value,omitempty"`
	Values   []string      `json:"values,omitempty"`
	Negate   bool          `json:"negate,omitempty"`

	Logic    LogicOp      `json:"logic,omitempty"`
	Children []*Condition `json:"children,omitempty"`

	// Timezone scopes time-based leaves (business_hours, day_of_week) to a
	// named IANA zone. "" means EvalInput.Defaults.Timezone, or the device's
	// local zone if that too is unset.
	Timezone string `json:"tz,omitempty"`

	// Specificity, when non-nil, overrides this subtree's computed
	// contribution (see specificity.go). Authoring escape hatch for a policy
	// console that wants to force a rule's precedence explicitly; the agent
	// honors it without question.
	Specificity *int `json:"specificity,omitempty"`
}

// isLeaf reports whether c is a leaf node (Kind set). isLeaf and isBranch are
// mutually exclusive for a structurally valid Condition; Compile rejects a
// node that is neither or both.
func (c *Condition) isLeaf() bool {
	return c != nil && c.Kind != ""
}

func (c *Condition) isBranch() bool {
	return c != nil && c.Logic != ""
}

// isWildcard reports whether c matches unconditionally: nil, or the zero
// value (no Kind and no Logic).
func (c *Condition) isWildcard() bool {
	return c == nil || (c.Kind == "" && c.Logic == "")
}

// Structural caps enforced by Compile. A compromised or merely buggy backend
// must not be able to stack-overflow or CPU-starve request evaluation by
// shipping a pathological condition tree.
const (
	// MaxConditionDepth bounds recursion depth of a single Condition tree.
	MaxConditionDepth = 32
	// MaxConditionNodes bounds the total node count (leaves + branches) of a
	// single Condition tree.
	MaxConditionNodes = 512
	// MaxRulesPerBundle bounds how many rules a single policy bundle may carry.
	MaxRulesPerBundle = 20000
)

// ExplainStep records one node's evaluation for Decision.Explain, populated
// only when EvalInput.Explain is set (an expensive, debug-only path — never on
// the hot request path by default).
type ExplainStep struct {
	Kind     ConditionKind `json:"kind,omitempty"`
	Logic    LogicOp       `json:"logic,omitempty"`
	Operator Operator      `json:"op,omitempty"`
	Value    string        `json:"value,omitempty"`
	Result   Tri           `json:"result"`
	// Depth is this node's distance from the tree root, for rendering an
	// indented trace.
	Depth int `json:"depth"`
}
