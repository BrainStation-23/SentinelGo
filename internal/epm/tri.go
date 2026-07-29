package epm

// Tri is a three-valued logic result: a condition matched, did not match, or
// could not be evaluated at all because the fact it depends on is not known
// (not yet collected, stale beyond the matcher's MaxAge, or the platform
// cannot supply it). Unknown is never silently treated as false — see
// Engine.EvaluateV2 and RuleV2.OnUnknown for how a rule's verdict family
// determines whether an Unknown condition causes the rule to match or not.
type Tri uint8

const (
	TriFalse Tri = iota
	TriTrue
	TriUnknown
)

// String renders t for logs and Explain traces.
func (t Tri) String() string {
	switch t {
	case TriTrue:
		return "true"
	case TriFalse:
		return "false"
	default:
		return "unknown"
	}
}

// triAnd combines two tri-state results with the same short-circuit rules as
// boolean AND, except that Unknown only propagates when it cannot be resolved
// by the other operand: False AND Unknown is False (a single false leaf is
// enough to fail an AND, regardless of what else is unknown), but True AND
// Unknown is Unknown (both operands would need to be true).
func triAnd(a, b Tri) Tri {
	if a == TriFalse || b == TriFalse {
		return TriFalse
	}
	if a == TriUnknown || b == TriUnknown {
		return TriUnknown
	}
	return TriTrue
}

// triOr is triAnd's dual: True OR Unknown is True (one true leaf is enough),
// False OR Unknown is Unknown.
func triOr(a, b Tri) Tri {
	if a == TriTrue || b == TriTrue {
		return TriTrue
	}
	if a == TriUnknown || b == TriUnknown {
		return TriUnknown
	}
	return TriFalse
}

// triNot inverts True/False and leaves Unknown as Unknown: the negation of an
// unverifiable fact is still unverifiable, not the opposite guess.
func triNot(a Tri) Tri {
	switch a {
	case TriTrue:
		return TriFalse
	case TriFalse:
		return TriTrue
	default:
		return TriUnknown
	}
}

// triFromBool lifts a plain boolean into Tri space.
func triFromBool(b bool) Tri {
	if b {
		return TriTrue
	}
	return TriFalse
}
