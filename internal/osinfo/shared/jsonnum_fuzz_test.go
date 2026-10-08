package shared

// The seed corpus runs as an ordinary unit test under `go test ./...`.
// To fuzz: go test -run='^$' -fuzz='^FuzzJSONNumbers$' -fuzztime=1m ./internal/osinfo/shared/

import (
	"math"
	"testing"
)

func FuzzJSONNumbers(f *testing.F) {
	for _, v := range []float64{
		0, 1, 1.9, -1, -0.5, 4294967295, 1e300, -1e300,
		math.MaxInt64, -math.MaxInt64 - 1, math.MaxUint64, math.NaN(), math.Inf(1), math.Inf(-1),
		math.SmallestNonzeroFloat64,
	} {
		f.Add(v)
	}

	f.Fuzz(func(t *testing.T, v float64) {
		if u, ok := JSONUint64(v); ok {
			if math.IsNaN(v) || v < 0 || v >= math.MaxUint64 {
				t.Fatalf("JSONUint64(%v) = %d, true; want ok=false", v, u)
			}
			if v < 1<<53 && u != uint64(math.Trunc(v)) {
				t.Fatalf("JSONUint64(%v) = %d, not a truncation", v, u)
			}
		}
		if i, ok := JSONInt(v); ok {
			if math.IsNaN(v) || v < math.MinInt || v >= math.MaxInt {
				t.Fatalf("JSONInt(%v) = %d, true; want ok=false", v, i)
			}
			if (v >= 0) != (i >= 0) && i != 0 {
				t.Fatalf("JSONInt(%v) = %d changed sign", v, i)
			}
		}
	})
}

func TestJSONNumbers(t *testing.T) {
	if u, ok := JSONUint64(512110190592); !ok || u != 512110190592 {
		t.Errorf("JSONUint64(512110190592) = %d, %v", u, ok)
	}
	if _, ok := JSONUint64(-1); ok {
		t.Error("JSONUint64(-1) accepted a negative value")
	}
	if _, ok := JSONInt(1e300); ok {
		t.Error("JSONInt(1e300) accepted an out-of-range value")
	}
	if i, ok := JSONInt(3); !ok || i != 3 {
		t.Errorf("JSONInt(3) = %d, %v", i, ok)
	}
}
