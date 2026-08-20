package task

import (
	"strings"
	"testing"
)

func TestBoundedTaskOutputTruncatesWithoutBackpressuringProcess(t *testing.T) {
	out := newBoundedTaskOutput(4)
	n, err := out.Write([]byte("sensitive-output"))
	if err != nil || n != len("sensitive-output") {
		t.Fatalf("Write() = (%d, %v), want full input accepted", n, err)
	}
	if got := out.String(); got != "sens\n[output truncated at 1 MiB]" {
		t.Fatalf("String() = %q", got)
	}
}

func TestBoundedTaskOutputKeepsOutputBelowLimit(t *testing.T) {
	out := newBoundedTaskOutput(32)
	_, _ = out.Write([]byte(strings.Repeat("x", 16)))
	if got := out.String(); got != strings.Repeat("x", 16) {
		t.Fatalf("String() = %q", got)
	}
}
