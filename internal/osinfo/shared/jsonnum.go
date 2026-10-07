package shared

import "math"

// JSON numbers decode as float64, and Go's float-to-integer conversion is
// implementation-defined for values outside the target range (e.g. a negative
// float to uint64, or 1e300 to int). PowerShell/WMI output is parsed this way,
// so these helpers range-check before converting and report ok=false instead
// of producing a garbage size, index or status code.

// JSONUint64 converts a decoded JSON number to uint64. ok is false for NaN,
// negative values and values >= 2^64. Fractions are truncated.
func JSONUint64(f float64) (uint64, bool) {
	// float64(math.MaxUint64) rounds up to 2^64, so the bound is exclusive.
	if math.IsNaN(f) || f < 0 || f >= math.MaxUint64 {
		return 0, false
	}
	return uint64(f), true
}

// JSONInt converts a decoded JSON number to int. ok is false for NaN and values
// outside the int range. Fractions are truncated.
func JSONInt(f float64) (int, bool) {
	// float64(math.MaxInt) rounds up to 2^63 on 64-bit, so the bound is exclusive.
	if math.IsNaN(f) || f < math.MinInt || f >= math.MaxInt {
		return 0, false
	}
	return int(f), true
}
