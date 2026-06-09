package shared

import (
	"regexp"
	"strconv"
)

func ParseDisplaySizeFromName(name string) float64 {
	re := regexp.MustCompile(`(\d+(?:\.\d+)?)\s*(?:["\']|inch|inches|"-|" )`)
	matches := re.FindStringSubmatch(name)
	if len(matches) > 1 {
		if size, err := strconv.ParseFloat(matches[1], 64); err == nil {
			return size
		}
	}
	return 0
}
