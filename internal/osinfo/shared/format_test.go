package shared_test

import (
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

func TestParseDisplaySizeFromName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want float64
	}{
		{"double quote", `Dell U2720Q 27"`, 27},
		{"decimal with double quote", `Built-in Retina Display 15.6" FHD`, 15.6},
		{"single quote", `HP 24'`, 24},
		{"space before quote", `Acer 21.5 "`, 21.5},
		{"inch word", "LG UltraWide 34 inch", 34},
		{"inch word without space", "Samsung 32inch", 32},
		{"inches word", "BenQ 27 inches", 27},
		{"quote followed by dash", `ASUS 23.8"-Monitor`, 23.8},
		{"resolution digits ignored", `1920x1080 24" panel`, 24},
		{"first size wins", `27" or 32"`, 27},
		{"no size", "Generic PnP Monitor", 0},
		{"digits without unit", "Dell P2419H", 0},
		{"empty", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shared.ParseDisplaySizeFromName(tt.in); got != tt.want {
				t.Errorf("ParseDisplaySizeFromName(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
