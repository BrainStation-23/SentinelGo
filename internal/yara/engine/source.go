package engine

import (
	"errors"
	"strings"
)

// errInclude is returned for a ruleset that uses include: rules come from one
// Storage object per ruleset, and compiling never touches the file system.
var errInclude = errors.New("include directives are not allowed")

// topLevel is what prepare finds outside rule bodies.
type topLevel struct {
	imports   []importDecl
	externals map[string]bool
	include   bool
}

// importDecl is an `import "name"` statement; [start, end) covers it in the
// source.
type importDecl struct {
	name       string
	start, end int
}

// scanTopLevel is a small lexer over YARA source. It skips comments, string
// literals and, inside rule bodies, regular expressions (YARA writes integer
// division as `\`, so `/` there always starts a regex or a comment), and
// records the import, include and external declarations at brace depth 0.
// It only has to be right about what is at depth 0: anything it misreads
// still goes through go-yara's own parser, and include is also blocked by the
// compiler's unusable base directory.
func scanTopLevel(src string) topLevel {
	tl := topLevel{externals: map[string]bool{}}
	type tok struct {
		ident      string // identifier, or "" for a string literal
		str        string // string literal contents
		start, end int
	}
	var toks []tok // depth-0 tokens of the current statement window
	depth := 0
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				i = len(src)
			} else {
				i += end + 4
			}
		case c == '"':
			start := i
			i++
			var b strings.Builder
			for i < len(src) && src[i] != '"' && src[i] != '\n' {
				if src[i] == '\\' && i+1 < len(src) {
					b.WriteByte(src[i])
					i++
				}
				b.WriteByte(src[i])
				i++
			}
			if i < len(src) && src[i] == '"' {
				i++
			}
			if depth == 0 {
				toks = append(toks, tok{str: b.String(), start: start, end: i})
			}
		case c == '/' && depth > 0:
			i++
			for i < len(src) && src[i] != '/' && src[i] != '\n' {
				if src[i] == '\\' {
					i++
				}
				i++
			}
			i++
		case c == '{':
			depth++
			i++
		case c == '}':
			if depth > 0 {
				depth--
			}
			i++
		case isIdentStart(c):
			start := i
			for i < len(src) && isIdentChar(src[i]) {
				i++
			}
			if depth == 0 {
				toks = append(toks, tok{ident: src[start:i], start: start, end: i})
			}
		default:
			i++
		}
	}
	for k, t := range toks {
		switch t.ident {
		case "include":
			tl.include = true
		case "import":
			if k+1 < len(toks) && toks[k+1].ident == "" {
				tl.imports = append(tl.imports, importDecl{name: toks[k+1].str, start: t.start, end: toks[k+1].end})
			}
		case "external":
			if k+1 < len(toks) && toks[k+1].ident != "" {
				tl.externals[toks[k+1].ident] = true
			}
		}
	}
	return tl
}

func isIdentStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isIdentChar(c byte) bool { return isIdentStart(c) || c >= '0' && c <= '9' }

// externalNames are the externals every ruleset gets, as the yara CLI and
// most scanners define them.
var externalNames = []string{"filename", "filepath", "extension", "filetype"}

// prepare rewrites a ruleset's source for go-yara: imports of modules the
// engine doesn't have are blanked out (so only the rules that use them are
// skipped, as unsupported_module:<name>, instead of the whole ruleset
// failing), and the standard externals are declared at the end, unless the
// source declares them itself. Blanking keeps every byte offset and line
// number, so go-yara's positions stay those of the original source.
func prepare(src string, supported map[string]bool) (string, error) {
	tl := scanTopLevel(src)
	if tl.include {
		return "", errInclude
	}
	b := []byte(src)
	for _, imp := range tl.imports {
		if supported[imp.name] {
			continue
		}
		for i := imp.start; i < imp.end; i++ {
			if b[i] != '\n' {
				b[i] = ' '
			}
		}
	}
	var decl strings.Builder
	for _, name := range externalNames {
		if !tl.externals[name] {
			decl.WriteString(" external ")
			decl.WriteString(name)
		}
	}
	if decl.Len() == 0 {
		return string(b), nil
	}
	return string(b) + "\n" + decl.String() + "\n", nil
}
