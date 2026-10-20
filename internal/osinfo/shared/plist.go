package shared

import (
	"encoding/xml"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
)

// DecodePlistXML decodes an XML property list (what `plutil -convert xml1`,
// `pwpolicy` and `dscl` print) into Go values: dict -> map[string]any,
// array -> []any, string/data -> string, integer -> int64, real -> float64,
// true/false -> bool, date -> time.Time. Binary plists must be converted
// with plutil first. Pure Go, so it builds everywhere and is unit-tested on
// any platform even though only the macOS collectors call it.
func DecodePlistXML(data []byte) (any, error) {
	d := xml.NewDecoder(strings.NewReader(string(data)))
	// Plists are ASCII/UTF-8; tolerate a declared charset we don't map.
	d.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, err
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local != "plist" {
			return decodePlistValue(d, se)
		}
	}
}

// errPlistShape reports an element the decoder doesn't understand.
var errPlistShape = errors.New("plist: unexpected element")

func decodePlistValue(d *xml.Decoder, se xml.StartElement) (any, error) {
	switch se.Name.Local {
	case "dict":
		return decodePlistDict(d)
	case "array":
		return decodePlistArray(d)
	case "true", "false":
		if err := d.Skip(); err != nil {
			return nil, err
		}
		return se.Name.Local == "true", nil
	}
	var text string
	if err := d.DecodeElement(&text, &se); err != nil {
		return nil, err
	}
	text = strings.TrimSpace(text)
	switch se.Name.Local {
	case "string", "data":
		return text, nil
	case "integer":
		return parsePlistInteger(text)
	case "real":
		return strconv.ParseFloat(text, 64)
	case "date":
		return time.Parse(time.RFC3339, text)
	}
	return nil, errPlistShape
}

// parsePlistInteger parses a plist integer. IOKit numbers are unsigned
// 64-bit, so ioreg writes a negative value (a discharging battery's
// InstantAmperage) as its two's complement, e.g. 18446744073709550616 for
// -1000. Such a value is wrapped back to the signed number it stands for
// instead of failing the whole plist.
func parsePlistInteger(text string) (int64, error) {
	n, err := strconv.ParseInt(text, 10, 64)
	if err == nil {
		return n, nil
	}
	u, uerr := strconv.ParseUint(text, 10, 64)
	if uerr != nil {
		return 0, err
	}
	// ParseInt failed, so u > MaxInt64 and its complement fits in an int64:
	// -^u - 1 is the two's-complement value without an unchecked conversion.
	if c := ^u; c <= math.MaxInt64 {
		return -int64(c) - 1, nil
	}
	return 0, err
}

func decodePlistDict(d *xml.Decoder) (map[string]any, error) {
	out := map[string]any{}
	key := ""
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.EndElement:
			return out, nil
		case xml.StartElement:
			if t.Name.Local == "key" {
				if err := d.DecodeElement(&key, &t); err != nil {
					return nil, err
				}
				continue
			}
			v, err := decodePlistValue(d, t)
			if err != nil {
				return nil, err
			}
			out[key] = v
		}
	}
}

func decodePlistArray(d *xml.Decoder) ([]any, error) {
	var out []any
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.EndElement:
			return out, nil
		case xml.StartElement:
			v, err := decodePlistValue(d, t)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
	}
}

// PlistFromOutput decodes the plist embedded in a command's output, skipping
// any text before it (pwpolicy prints "Getting global account policies",
// dscl prints "accountPolicyData:").
func PlistFromOutput(out string) (any, bool) {
	i := strings.Index(out, "<?xml")
	if i < 0 {
		i = strings.Index(out, "<plist")
	}
	if i < 0 {
		return nil, false
	}
	v, err := DecodePlistXML([]byte(out[i:]))
	return v, err == nil
}

// PlistNumber returns a plist integer or real as float64.
func PlistNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case int64:
		return float64(n), true
	case float64:
		return n, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(n), 64)
		return f, err == nil
	}
	return 0, false
}

// PlistInt returns a plist integer or real as an int. ok is false when v is
// not a number or lies outside the int32 range, so a hostile or corrupt plist
// can't overflow the conversion on any platform.
func PlistInt(v any) (int, bool) {
	f, ok := v.(float64)
	if s, isStr := v.(string); isStr {
		var err error
		f, err = strconv.ParseFloat(strings.TrimSpace(s), 64)
		ok = err == nil
	}
	if ok {
		if math.IsNaN(f) || f < math.MinInt32 || f > math.MaxInt32 {
			return 0, false
		}
		return int32Int(int64(f))
	}
	if n, isInt := v.(int64); isInt {
		return int32Int(n)
	}
	return 0, false
}

// int32Int narrows n to an int when it fits in an int32.
func int32Int(n int64) (int, bool) {
	if n < math.MinInt32 || n > math.MaxInt32 {
		return 0, false
	}
	return int(n), true
}

// PlistBool returns a plist boolean, also accepting 0/1 numbers and
// "true"/"1"-style strings, which `defaults write` often leaves behind.
func PlistBool(v any) (bool, bool) {
	switch b := v.(type) {
	case bool:
		return b, true
	case string:
		switch strings.ToLower(strings.TrimSpace(b)) {
		case "1", "true", "yes":
			return true, true
		case "0", "false", "no":
			return false, true
		}
		return false, false
	}
	if n, ok := PlistNumber(v); ok {
		return n != 0, true
	}
	return false, false
}
