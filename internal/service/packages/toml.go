package packages

import (
	"bufio"
	"bytes"
	"strings"
)

// tomlEntry is one table of a TOML array of tables ([[package]]): its
// top-level keys with their raw values (strings unquoted), and the names of
// its subtables ([package.source], [[package.wheels]]).
type tomlEntry struct {
	keys      map[string]string
	subtables map[string]bool
}

// tomlArrayTables reads the [[name]] tables of a lockfile. It reads only
// one-line key/value pairs and table headers, which is all the lockfiles it
// serves use for the fields read here, so no TOML library is needed. Values
// of multi-line arrays are skipped, so an array element that looks like
// `key = value` is never read as a key.
func tomlArrayTables(data []byte, name string) []tomlEntry {
	var out []tomlEntry
	var cur *tomlEntry // the [[name]] table being read
	inSub := false     // keys belong to a subtable of cur, not cur itself
	header := "[[" + name + "]]"
	sub := name + "."
	depth := 0 // open brackets of a multi-line array value
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimRight(sc.Text(), "\r"))
		if depth > 0 {
			depth += bracketBalance(line)
			continue
		}
		if line == "" || line[0] == '#' {
			continue
		}
		if line[0] == '[' {
			switch {
			case line == header:
				out = append(out, tomlEntry{keys: map[string]string{}, subtables: map[string]bool{}})
				cur, inSub = &out[len(out)-1], false
			case cur != nil && (strings.HasPrefix(line, "["+sub) || strings.HasPrefix(line, "[["+sub)):
				t := strings.TrimPrefix(strings.Trim(line, "[] "), sub)
				if i := strings.IndexByte(t, '.'); i >= 0 {
					t = t[:i]
				}
				cur.subtables[t] = true
				inSub = true
			default:
				cur = nil
			}
			continue
		}
		key, value, ok := tomlKeyValue(line)
		if !ok {
			continue
		}
		if strings.HasPrefix(value, "[") {
			if d := bracketBalance(value); d > 0 {
				depth = d
			}
		}
		if cur != nil && !inSub {
			if _, dup := cur.keys[key]; !dup {
				cur.keys[key] = value
			}
		}
	}
	return out
}

// bracketBalance returns the "[" minus "]" in s, outside basic strings.
func bracketBalance(s string) int {
	n, inString := 0, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && inString:
			i++
		case c == '"':
			inString = !inString
		case c == '[' && !inString:
			n++
		case c == ']' && !inString:
			n--
		}
	}
	return n
}
