package filescan

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

// rtfSkipDestinations are groups that hold no document text.
var rtfSkipDestinations = map[string]bool{
	"fonttbl": true, "colortbl": true, "stylesheet": true, "info": true, "pict": true,
	"object": true, "objdata": true, "themedata": true, "colorschememapping": true,
	"datastore": true, "latentstyles": true, "listtable": true, "listoverridetable": true,
	"rsidtbl": true, "generator": true, "xmlnstbl": true, "filetbl": true, "revtbl": true,
	"pgdsctbl": true, "mmathPr": true, "fldinst": true, "bkmkstart": true, "bkmkend": true,
}

// rtfMaxDepth bounds group nesting; deeper is treated as corrupt.
const rtfMaxDepth = 1024

// cp1252High maps bytes 0x80–0x9f of Windows-1252, which \'hh escapes use;
// 0 means unused. Other bytes are Latin-1.
var cp1252High = [32]rune{
	0x20ac, 0, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021, 0x02c6, 0x2030, 0x0160, 0x2039, 0x0152, 0, 0x017d, 0,
	0, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014, 0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0, 0x017e, 0x0178,
}

func cp1252(b byte) rune {
	if b >= 0x80 && b < 0xa0 {
		if r := cp1252High[b-0x80]; r != 0 {
			return r
		}
		return '?'
	}
	return rune(b)
}

type rtfGroup struct {
	skip bool
	uc   int // characters to skip after \uN
}

// extractRTF writes the text of an RTF document to sink: control words,
// tables and embedded objects are dropped, \'hh and \uN escapes decoded.
func extractRTF(r io.Reader, sink *textSink) error {
	br := bufio.NewReaderSize(r, textReadBytes)
	p := &rtfParser{br: br, sink: sink, stack: []rtfGroup{{uc: 1}}}
	return p.run()
}

type rtfParser struct {
	br        *bufio.Reader
	sink      *textSink
	stack     []rtfGroup
	sb        strings.Builder
	skipChars int // fallback characters still to drop after \uN
}

func (p *rtfParser) top() *rtfGroup { return &p.stack[len(p.stack)-1] }

func (p *rtfParser) emit(s string) error {
	if p.top().skip {
		return nil
	}
	if p.skipChars > 0 {
		p.skipChars--
		return nil
	}
	p.sb.WriteString(s)
	if p.sb.Len() >= textReadBytes {
		return p.flush()
	}
	return nil
}

func (p *rtfParser) flush() error {
	if p.sb.Len() == 0 {
		return nil
	}
	err := p.sink.WriteString(p.sb.String())
	p.sb.Reset()
	return err
}

func (p *rtfParser) run() error {
	for {
		c, err := p.br.ReadByte()
		if err != nil {
			if ferr := p.flush(); ferr != nil {
				return ferr
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		switch c {
		case '{':
			if len(p.stack) >= rtfMaxDepth {
				_ = p.flush()
				return errCorrupt
			}
			p.stack = append(p.stack, *p.top())
		case '}':
			if len(p.stack) > 1 {
				p.stack = p.stack[:len(p.stack)-1]
			}
		case '\\':
			if err := p.control(); err != nil {
				return err
			}
		case '\r', '\n':
		default:
			if err := p.emit(string(cp1252(c))); err != nil {
				return err
			}
		}
	}
}

// control handles what follows a backslash.
func (p *rtfParser) control() error {
	c, err := p.br.ReadByte()
	if err != nil {
		return nil // a trailing backslash: the loop sees EOF next
	}
	switch {
	case c == '\'':
		var hex [2]byte
		if _, err := io.ReadFull(p.br, hex[:]); err != nil {
			return nil
		}
		v, ok := hexByte(hex[0], hex[1])
		if !ok {
			return nil
		}
		return p.emit(string(cp1252(v)))
	case c == '*':
		p.top().skip = true // an optional destination this reader doesn't know
		return nil
	case c == '\\' || c == '{' || c == '}':
		return p.emit(string(c))
	case c == '~':
		return p.emit(" ")
	case c == '_':
		return p.emit("-")
	case c == '\r' || c == '\n':
		return p.emit("\n")
	case isLetter(c):
		return p.word(c)
	}
	return nil // other control symbols (\-, \|, \:) carry no text
}

// word reads a control word and its optional numeric parameter.
func (p *rtfParser) word(first byte) error {
	name := []byte{first}
	for len(name) < 32 {
		c, err := p.br.ReadByte()
		if err != nil {
			break
		}
		if !isLetter(c) {
			_ = p.br.UnreadByte()
			break
		}
		name = append(name, c)
	}
	param, hasParam := 0, false
	neg := false
	if c, err := p.br.ReadByte(); err == nil {
		if c == '-' {
			neg = true
		} else {
			_ = p.br.UnreadByte()
		}
	}
	for digits := 0; digits < 10; digits++ {
		c, err := p.br.ReadByte()
		if err != nil {
			break
		}
		if c < '0' || c > '9' {
			_ = p.br.UnreadByte()
			break
		}
		param, hasParam = param*10+int(c-'0'), true
	}
	if neg {
		param = -param
	}
	if c, err := p.br.ReadByte(); err == nil && c != ' ' {
		_ = p.br.UnreadByte() // the space after a control word belongs to it
	}

	w := string(name)
	switch {
	case rtfSkipDestinations[w]:
		p.top().skip = true
	case w == "par" || w == "line" || w == "sect" || w == "page" || w == "row":
		return p.emit("\n")
	case w == "cell" || w == "tab":
		return p.emit("\t")
	case w == "uc" && hasParam:
		p.top().uc = min(max(param, 0), 8)
	case w == "u" && hasParam:
		if param < 0 {
			param += 65536
		}
		err := p.emit(string(rune(param)))
		p.skipChars = p.top().uc
		return err
	case w == "bin" && hasParam && param > 0:
		_, err := p.br.Discard(param) // binary data, never text
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return nil
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func hexByte(a, b byte) (byte, bool) {
	h, ok1 := hexVal(a)
	l, ok2 := hexVal(b)
	return h<<4 | l, ok1 && ok2
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
