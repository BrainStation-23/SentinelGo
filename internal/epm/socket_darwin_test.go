//go:build darwin

package epm

import (
	"reflect"
	"testing"
)

func TestSplitArgs_Empty(t *testing.T) {
	got := splitArgs("")
	if len(got) != 0 {
		t.Errorf("splitArgs(\"\") = %v, want empty", got)
	}
}

func TestSplitArgs_MultipleTokens(t *testing.T) {
	got := splitArgs("--flag value --other")
	want := []string{"--flag", "value", "--other"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("splitArgs = %v, want %v", got, want)
	}
}

func TestSplitArgs_CollapsesExtraWhitespace(t *testing.T) {
	got := splitArgs("  --flag   value  ")
	want := []string{"--flag", "value"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("splitArgs = %v, want %v", got, want)
	}
}
