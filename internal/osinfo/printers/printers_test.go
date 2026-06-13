package printers

import (
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

func TestNewPrinter(t *testing.T) {
	p := newPrinter("HP LaserJet", "Black and white", 600, 600)
	if p.Description != "HP LaserJet" {
		t.Errorf("Description = %q, want %q", p.Description, "HP LaserJet")
	}
	if p.PrintingType != "Black and white" {
		t.Errorf("PrintingType = %q, want %q", p.PrintingType, "Black and white")
	}
	if p.PrintingResolution.HorizontalDPI != 600 {
		t.Errorf("HorizontalDPI = %d, want 600", p.PrintingResolution.HorizontalDPI)
	}
	if p.PrintingResolution.VerticalDPI != 600 {
		t.Errorf("VerticalDPI = %d, want 600", p.PrintingResolution.VerticalDPI)
	}
	if p.LocationType != "Local" {
		t.Errorf("LocationType = %q, want %q", p.LocationType, "Local")
	}
	if p.MarkingType != "Unknown" {
		t.Errorf("MarkingType = %q, want %q", p.MarkingType, "Unknown")
	}
}

func TestNewPrinterZeroDPI(t *testing.T) {
	p := newPrinter("Colorful Inkjet", "Colorful", 0, 0)
	if p.PrintingResolution != (shared.PrintingResolution{}) {
		t.Errorf("expected zero resolution, got %+v", p.PrintingResolution)
	}
}

func TestGetReturnsSlice(t *testing.T) {
	// Smoke test: Get() must not panic regardless of what system tools return.
	printers := Get()
	// Result may be nil or non-nil depending on the OS environment; just assert no panic.
	_ = printers
}
