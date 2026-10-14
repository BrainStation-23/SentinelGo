package security

// Compliance telemetry (#172): the optional security_info keys defined in the
// "Compliance telemetry" section of sentinel-ops docs/agent-ingestion.md.
//
// compliance_<os>.go gathers the raw values; the parsers live in the
// compliance_*parse.go files, which have no OS suffix so every one of them
// compiles and is unit-tested on any platform. A probe that can't read its
// value returns nil, which leaves the key out of the payload: the server then
// shows that check as unknown instead of failing it.

import (
	"encoding/json"
	"strings"
	"unicode/utf16"
)

// maxMissingUpdates caps patching.missing_updates so a long-neglected
// machine can't bloat the inventory payload.
const maxMissingUpdates = 100

// decodePSObjects decodes PowerShell ConvertTo-Json output, which is a bare
// object for one item and an array for several.
func decodePSObjects(output string) []map[string]any {
	output = strings.TrimSpace(output)
	var rows []map[string]any
	if err := json.Unmarshal([]byte(output), &rows); err == nil {
		return rows
	}
	var single map[string]any
	if json.Unmarshal([]byte(output), &single) != nil {
		return nil
	}
	return []map[string]any{single}
}

// decodeText returns a file's text, decoding UTF-16 when the file starts with
// a byte-order mark (secedit writes its export as UTF-16LE) and stripping a
// UTF-8 BOM otherwise.
func decodeText(b []byte) string {
	if len(b) >= 2 && ((b[0] == 0xFF && b[1] == 0xFE) || (b[0] == 0xFE && b[1] == 0xFF)) {
		littleEndian := b[0] == 0xFF
		b = b[2:]
		u := make([]uint16, len(b)/2)
		for i := range u {
			if littleEndian {
				u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
			} else {
				u[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
			}
		}
		return string(utf16.Decode(u))
	}
	return strings.TrimPrefix(string(b), "\xef\xbb\xbf")
}

// parseKeyValueConf parses "key = value" lines (pwquality.conf,
// faillock.conf, auditd.conf, ...). Keys are lower-cased; '#' starts a
// comment; a bare word is stored with an empty value; later lines win.
func parseKeyValueConf(content string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		out[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return out
}

// parseINI parses an INI file into section -> key -> value, with section
// names and keys lower-cased. Keys before any section go under "". '#' and
// ';' start comment lines.
func parseINI(content string) map[string]map[string]string {
	out := map[string]map[string]string{}
	section := ""
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if out[section] == nil {
			out[section] = map[string]string{}
		}
		out[section][strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return out
}

// truthy reports whether a config value means "on".
func truthy(v string) bool {
	switch strings.ToLower(strings.Trim(strings.TrimSpace(v), `"'`)) {
	case "1", "true", "yes", "on", "enabled":
		return true
	}
	return false
}

// nonZero returns &v, or nil when v is the zero value: a probe that read
// nothing leaves the whole key out instead of sending {}.
func nonZero[T comparable](v T) *T {
	var zero T
	if v == zero {
		return nil
	}
	return &v
}
