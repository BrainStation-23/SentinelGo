package disk

import (
	"testing"
)

func TestManufacturerFromModel(t *testing.T) {
	cases := []struct {
		model string
		want  string
	}{
		{"Samsung SSD 870 EVO 500GB", "Samsung"},
		{"SAMSUNG MZNLN256HAJQ", "Samsung"},
		{"WDC WD10EZEX-08WN4A0", "Western Digital"},
		{"WD Blue SN570", "Western Digital"},
		// Seagate drives that include the name explicitly
		{"Seagate ST2000DM008", "Seagate"},
		{"TOSHIBA MQ04ABF100", "Toshiba"},
		{"APPLE SSD AP1024Q", "Apple"},
		{"Intel SSDPEKNW512G8", "Intel"},
		// Crucial drives that include the name explicitly
		{"Crucial CT500MX500SSD1", "Crucial"},
		{"KINGSTON SA400S37240G", "Kingston"},
		{"SanDisk SSD PLUS 480GB", "SanDisk"},
		// SK Hynix drives where name is present
		{"SK Hynix PC711 512GB", "SK Hynix"},
		// Model-number-only strings not containing manufacturer name fall back to the model
		{"ST2000DM008-2FR102", "ST2000DM008-2FR102"},
		{"HFM512GD3JX013N", "HFM512GD3JX013N"},
		{"UnknownBrand XYZ", "UnknownBrand XYZ"},
		{"", ""},
	}
	for _, c := range cases {
		got := manufacturerFromModel(c.model)
		if got != c.want {
			t.Errorf("manufacturerFromModel(%q) = %q, want %q", c.model, got, c.want)
		}
	}
}
