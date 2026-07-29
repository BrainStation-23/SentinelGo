package epm

import "math"

// Base specificity weights, chosen so v1's five match tiers survive intact.
// v1 (legacy_engine.go) used legacyTierHash=300, legacyTierPublisher=200,
// legacyTierPathExact=100, legacyTierPathGlob=50, legacyTierWildcard=10 —
// those five numeric values are reproduced exactly below, and every new
// weight is placed either inside a 100-point band (so it cannot cross a v1
// tier boundary on its own) or, for genuinely new identity strength, at a
// value AND composition can never push out of that band — see the invariant
// note on andSpecificity.
const (
	WeightHash        = 300 // sha256, script_sha256, msi_product_code
	WeightHashWeak    = 280 // sha1 — a real but weaker cryptographic identity
	WeightBundleID    = 250
	WeightPublisher   = 200
	WeightPackage     = 190
	WeightProductName = 150
	WeightPathExact   = 100
	WeightFileName    = 80
	WeightArgsExact   = 60
	WeightServiceName = 60
	WeightPathGlob    = 50
	WeightUser        = 40
	WeightParentChild = 40
	WeightUserGroup   = 30
	WeightOrgUnit     = 20 // device_group, org, department
	// WeightPosture covers disk_encryption, secure_boot, firewall, antivirus,
	// compliance, network_type, vpn_active, corporate_network, business_hours,
	// day_of_week, os_version: these SCOPE a rule (narrow who/when it applies)
	// rather than IDENTIFY the target application, so they deliberately carry
	// the same low weight as an unconstrained wildcard rule.
	WeightPosture  = 10
	WeightWildcard = 10 // empty condition tree — equals v1's tierWildcard exactly
)

// operatorDiscount scales a leaf's Weight by how strongly its operator
// asserts a match. An exact/set/boolean comparison earns the full weight; a
// pattern or range comparison, which matches a broader set of actual values
// for the same authored Value, earns less.
var operatorDiscount = map[Operator]float64{
	OpEquals: 1.00,
	OpIn:     1.00,
	OpIsTrue: 1.00, OpIsFalse: 1.00,
	OpPrefix: 0.60, OpSuffix: 0.60, OpContains: 0.60,
	OpGlob: 0.50, OpRegex: 0.50,
	OpVersionGTE: 0.40, OpVersionLT: 0.40, OpBetween: 0.40,
}

// discountFor returns op's discount factor, defaulting to 1.0 for an operator
// with no entry above (there is none among the declared Operator constants,
// but a future addition should not silently score as zero).
func discountFor(op Operator) float64 {
	if d, ok := operatorDiscount[op]; ok {
		return d
	}
	return 1.0
}

// negateDiscount scales a negated leaf's weight: "not X" asserts far less
// about the target than "X" does, so it should never be able to outrank the
// positive assertion it inverts.
const negateDiscount = 0.25

// notDiscount is the same discount factor applied to a NOT branch's
// contribution — kept as a distinct name from negateDiscount (leaf-level) even
// though the value is identical, so the two call sites read independently.
const notDiscount = 0.25

// andSiblingCap bounds how much AND's non-maximum children may add on top of
// the maximum child's weight (see andSpecificity). Because base tiers are
// spaced at least 50 points apart and the largest is 300, capping the sibling
// contribution at 99 guarantees a composite AND can never cross into the next
// tier up: a rule whose strongest identity condition is publisher (200) can
// reach at most 299 and can never outrank any rule carrying a hash (300).
// That is the invariant that keeps v1's tier ordering intact while still
// letting `hash AND user AND business_hours` legitimately outrank bare hash.
const andSiblingCap = 99

// leafSpecificity scores a single leaf Condition.
func leafSpecificity(weight int, op Operator, negate bool) int {
	score := float64(weight) * discountFor(op)
	if negate {
		score *= negateDiscount
	}
	return int(math.Round(score))
}

// andSpecificity composes an AND branch's children. See andSiblingCap for why
// the non-maximum contribution is capped rather than simply summed.
func andSpecificity(children []int) int {
	if len(children) == 0 {
		return WeightWildcard
	}
	maxIdx := 0
	for i, c := range children[1:] {
		if c > children[maxIdx] {
			maxIdx = i + 1
		}
	}
	max := children[maxIdx]

	var rest int
	for i, c := range children {
		if i == maxIdx {
			continue
		}
		rest += c
	}
	restContribution := rest / 4
	if restContribution > andSiblingCap {
		restContribution = andSiblingCap
	}
	return max + restContribution
}

// orSpecificity composes an OR branch: a disjunction is only as specific as
// its WEAKEST branch, because matching the rule only ever requires one branch
// to fire — the strong branches contribute nothing to how narrowly the rule
// actually targets a request. Used both for the static (compile-time) upper
// bound and, once evaluation identifies which branch actually matched, for
// the true per-request specificity (see compile.go's tree evaluator).
func orSpecificity(children []int) int {
	if len(children) == 0 {
		return WeightWildcard
	}
	min := children[0]
	for _, c := range children[1:] {
		if c < min {
			min = c
		}
	}
	return min
}

// notSpecificity composes a NOT branch: negation asserts less than its child,
// mirroring leafSpecificity's negateDiscount.
func notSpecificity(child int) int {
	return int(math.Round(float64(child) * notDiscount))
}
