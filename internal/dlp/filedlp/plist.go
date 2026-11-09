package filedlp

// A small reader for XML property lists (what `diskutil info -plist` and
// `ioreg -a` print): dict → map[string]any, array → []any, string, integer
// (int64), real (float64), true/false, data and date as their text.
// OS-independent so it is tested everywhere.

import (
	"encoding/xml"
	"errors"
	"io"
	"strconv"
	"strings"
)

// parsePlist decodes the top-level value of an XML property list.
func parsePlist(r io.Reader) (any, error) {
	d := xml.NewDecoder(r)
	d.Strict = false
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, err
		}
		if se, ok := tok.(xml.StartElement); ok {
			if se.Name.Local == "plist" {
				continue
			}
			return plistValue(d, se, 0)
		}
	}
}

const maxPlistDepth = 64

func plistValue(d *xml.Decoder, se xml.StartElement, depth int) (any, error) {
	if depth > maxPlistDepth {
		return nil, errors.New("plist nested too deep")
	}
	switch se.Name.Local {
	case "dict":
		m := map[string]any{}
		key := ""
		for {
			tok, err := d.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				if t.Name.Local == "key" {
					s, err := plistText(d)
					if err != nil {
						return nil, err
					}
					key = s
					continue
				}
				v, err := plistValue(d, t, depth+1)
				if err != nil {
					return nil, err
				}
				m[key] = v
			case xml.EndElement:
				return m, nil
			}
		}
	case "array":
		var a []any
		for {
			tok, err := d.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				v, err := plistValue(d, t, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			case xml.EndElement:
				return a, nil
			}
		}
	case "true", "false":
		if err := d.Skip(); err != nil {
			return nil, err
		}
		return se.Name.Local == "true", nil
	case "integer":
		s, err := plistText(d)
		if err != nil {
			return nil, err
		}
		n, err := strconv.ParseInt(strings.TrimSpace(s), 0, 64)
		if err != nil {
			u, uerr := strconv.ParseUint(strings.TrimSpace(s), 0, 64)
			if uerr != nil {
				return int64(0), nil //nolint:nilerr // an unreadable number is not fatal
			}
			return int64(u), nil // #nosec G115 -- ids beyond int64 wrap; only compared
		}
		return n, nil
	case "real":
		s, err := plistText(d)
		if err != nil {
			return nil, err
		}
		f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
		return f, nil
	default: // string, data, date
		return plistText(d)
	}
}

// plistText reads an element's text up to its end.
func plistText(d *xml.Decoder) (string, error) {
	var b strings.Builder
	for {
		tok, err := d.Token()
		if err != nil {
			return "", err
		}
		switch t := tok.(type) {
		case xml.CharData:
			b.Write(t)
		case xml.EndElement:
			return b.String(), nil
		case xml.StartElement:
			if err := d.Skip(); err != nil {
				return "", err
			}
		}
	}
}

func plistString(m map[string]any, k string) string { s, _ := m[k].(string); return s }
func plistBool(m map[string]any, k string) bool     { b, _ := m[k].(bool); return b }
func plistInt(m map[string]any, k string) (int64, bool) {
	n, ok := m[k].(int64)
	return n, ok
}
