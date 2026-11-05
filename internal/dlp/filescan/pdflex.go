package filescan

// A minimal PDF object lexer and parser (ISO 32000-1 §7.2–7.3), enough to
// read dictionaries, content streams and ToUnicode CMaps. It never fails on
// bad input: it returns what it could read and stops at the end of the data.

import (
	"strconv"
)

type pdfTokKind int

const (
	tokEOF pdfTokKind = iota
	tokDictOpen
	tokDictClose
	tokArrOpen
	tokArrClose
	tokName
	tokString // literal or hex string: val holds the decoded bytes
	tokNumber
	tokKeyword // operators, true/false/null, R, obj, stream, …
)

type pdfTok struct {
	kind pdfTokKind
	val  []byte
	num  float64
	pos  int // offset just past the token
}

type pdfLexer struct {
	b    []byte
	p    int
	peek []pdfTok
}

func isPDFSpace(c byte) bool {
	return c == 0 || c == '\t' || c == '\n' || c == '\f' || c == '\r' || c == ' '
}

func isPDFDelim(c byte) bool {
	switch c {
	case '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return true
	}
	return false
}

func (l *pdfLexer) next() pdfTok {
	if n := len(l.peek); n > 0 {
		t := l.peek[n-1]
		l.peek = l.peek[:n-1]
		return t
	}
	return l.scan()
}

// back pushes t back; tokens come out again in reverse order of back calls.
func (l *pdfLexer) back(t pdfTok) { l.peek = append(l.peek, t) }

func (l *pdfLexer) skipSpace() {
	for l.p < len(l.b) {
		c := l.b[l.p]
		switch {
		case isPDFSpace(c):
			l.p++
		case c == '%':
			for l.p < len(l.b) && l.b[l.p] != '\n' && l.b[l.p] != '\r' {
				l.p++
			}
		default:
			return
		}
	}
}

func (l *pdfLexer) scan() pdfTok {
	l.skipSpace()
	if l.p >= len(l.b) {
		return pdfTok{kind: tokEOF, pos: l.p}
	}
	c := l.b[l.p]
	switch c {
	case '<':
		if l.p+1 < len(l.b) && l.b[l.p+1] == '<' {
			l.p += 2
			return pdfTok{kind: tokDictOpen, pos: l.p}
		}
		return l.hexString()
	case '>':
		l.p++
		if l.p < len(l.b) && l.b[l.p] == '>' {
			l.p++
			return pdfTok{kind: tokDictClose, pos: l.p}
		}
		return l.scan() // a stray '>'
	case '[':
		l.p++
		return pdfTok{kind: tokArrOpen, pos: l.p}
	case ']':
		l.p++
		return pdfTok{kind: tokArrClose, pos: l.p}
	case '(':
		return l.literalString()
	case '/':
		return l.name()
	case ')', '{', '}':
		l.p++
		return l.scan()
	}
	start := l.p
	for l.p < len(l.b) && !isPDFSpace(l.b[l.p]) && !isPDFDelim(l.b[l.p]) {
		l.p++
	}
	word := l.b[start:l.p]
	if f, err := strconv.ParseFloat(string(word), 64); err == nil && isPDFNumber(word) {
		return pdfTok{kind: tokNumber, num: f, val: word, pos: l.p}
	}
	return pdfTok{kind: tokKeyword, val: word, pos: l.p}
}

func isPDFNumber(w []byte) bool {
	for _, c := range w {
		if (c < '0' || c > '9') && c != '.' && c != '-' && c != '+' {
			return false
		}
	}
	return len(w) > 0
}

func (l *pdfLexer) name() pdfTok {
	l.p++ // '/'
	var out []byte
	for l.p < len(l.b) && !isPDFSpace(l.b[l.p]) && !isPDFDelim(l.b[l.p]) {
		c := l.b[l.p]
		if c == '#' && l.p+2 < len(l.b) {
			if v, ok := hexByte(l.b[l.p+1], l.b[l.p+2]); ok {
				out = append(out, v)
				l.p += 3
				continue
			}
		}
		out = append(out, c)
		l.p++
	}
	return pdfTok{kind: tokName, val: out, pos: l.p}
}

func (l *pdfLexer) hexString() pdfTok {
	l.p++ // '<'
	var out []byte
	var hi byte
	half := false
	for l.p < len(l.b) && l.b[l.p] != '>' {
		if v, ok := hexVal(l.b[l.p]); ok {
			if half {
				out = append(out, hi<<4|v)
			} else {
				hi = v
			}
			half = !half
		}
		l.p++
	}
	if half {
		out = append(out, hi<<4)
	}
	if l.p < len(l.b) {
		l.p++ // '>'
	}
	return pdfTok{kind: tokString, val: out, pos: l.p}
}

func (l *pdfLexer) literalString() pdfTok {
	l.p++ // '('
	var out []byte
	depth := 1
	for l.p < len(l.b) {
		c := l.b[l.p]
		l.p++
		switch c {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return pdfTok{kind: tokString, val: out, pos: l.p}
			}
		case '\\':
			if l.p >= len(l.b) {
				continue
			}
			e := l.b[l.p]
			l.p++
			switch e {
			case 'n':
				c = '\n'
			case 'r':
				c = '\r'
			case 't':
				c = '\t'
			case 'b':
				c = '\b'
			case 'f':
				c = '\f'
			case '\r':
				if l.p < len(l.b) && l.b[l.p] == '\n' {
					l.p++
				}
				continue
			case '\n':
				continue
			default:
				if e >= '0' && e <= '7' {
					v := int(e - '0')
					for i := 0; i < 2 && l.p < len(l.b) && l.b[l.p] >= '0' && l.b[l.p] <= '7'; i++ {
						v = v*8 + int(l.b[l.p]-'0')
						l.p++
					}
					c = byte(v) // #nosec G115 -- three octal digits, truncated to a byte as the spec says
				} else {
					c = e
				}
			}
		}
		out = append(out, c)
	}
	return pdfTok{kind: tokString, val: out, pos: l.p}
}

// PDF values: pdfDict, pdfArray, pdfName, pdfString, float64, pdfRef, pdfKeyword.
type (
	pdfDict    map[string]any
	pdfArray   []any
	pdfName    string
	pdfString  []byte
	pdfRef     int
	pdfKeyword string
)

// maxPDFNesting bounds dictionaries and arrays inside each other.
const maxPDFNesting = 64

// value parses one value; ok is false at the end of the data or at a closing
// token the caller must handle (it is pushed back).
func (l *pdfLexer) value(depth int) (any, bool) {
	t := l.next()
	switch t.kind {
	case tokEOF:
		return nil, false
	case tokDictClose, tokArrClose:
		l.back(t)
		return nil, false
	case tokDictOpen:
		if depth >= maxPDFNesting {
			return nil, false
		}
		d := pdfDict{}
		for {
			k := l.next()
			if k.kind == tokDictClose || k.kind == tokEOF {
				return d, true
			}
			if k.kind != tokName {
				continue
			}
			v, ok := l.value(depth + 1)
			if !ok {
				if n := l.next(); n.kind != tokDictClose {
					l.back(n)
					continue
				}
				return d, true
			}
			d[string(k.val)] = v
		}
	case tokArrOpen:
		if depth >= maxPDFNesting {
			return nil, false
		}
		var a pdfArray
		for {
			v, ok := l.value(depth + 1)
			if !ok {
				n := l.next()
				if n.kind == tokArrClose || n.kind == tokEOF {
					return a, true
				}
				continue // a stray '>>'
			}
			a = append(a, v)
		}
	case tokName:
		return pdfName(t.val), true
	case tokString:
		return pdfString(t.val), true
	case tokNumber:
		// "12 0 R" is a reference
		g := l.next()
		if g.kind == tokNumber {
			r := l.next()
			if r.kind == tokKeyword && string(r.val) == "R" && t.num >= 0 && t.num < 1<<31 {
				return pdfRef(int(t.num)), true
			}
			l.back(r)
		}
		l.back(g)
		return t.num, true
	default:
		return pdfKeyword(t.val), true
	}
}

func (d pdfDict) name(key string) string {
	n, _ := d[key].(pdfName)
	return string(n)
}

// names returns a name or each name of an array of names (e.g. /Filter).
func (d pdfDict) names(key string) []string {
	switch v := d[key].(type) {
	case pdfName:
		return []string{string(v)}
	case pdfArray:
		var out []string
		for _, e := range v {
			n, _ := e.(pdfName)
			out = append(out, string(n))
		}
		return out
	}
	return nil
}
