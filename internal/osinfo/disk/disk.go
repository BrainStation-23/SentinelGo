package disk

import (
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// Get returns physical disk devices for the current platform.
func Get() []shared.DiskDevice {
	return getDisks()
}

var knownManufacturers = []struct {
	prefix string
	name   string
}{
	{"samsung", "Samsung"},
	{"western digital", "Western Digital"},
	{"wd", "Western Digital"},
	{"seagate", "Seagate"},
	{"toshiba", "Toshiba"},
	{"hitachi", "Hitachi"},
	{"hgst", "HGST"},
	{"apple", "Apple"},
	{"intel", "Intel"},
	{"micron", "Micron"},
	{"crucial", "Crucial"},
	{"sk hynix", "SK Hynix"},
	{"hynix", "SK Hynix"},
	{"kingston", "Kingston"},
	{"sandisk", "SanDisk"},
	{"corsair", "Corsair"},
	{"adata", "ADATA"},
	{"transcend", "Transcend"},
	{"sabrent", "Sabrent"},
	{"kingspec", "KingSpec"},
}

func manufacturerFromModel(model string) string {
	lower := strings.ToLower(model)
	for _, m := range knownManufacturers {
		if strings.HasPrefix(lower, m.prefix) || strings.Contains(lower, " "+m.prefix) {
			return m.name
		}
	}
	return model
}
