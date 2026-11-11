package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"
)

// FuzzCompile: no rule source crashes or hangs the compiler, and whatever
// compiles can scan.
func FuzzCompile(f *testing.F) {
	for _, s := range []string{
		eicarRule,
		`import "pe" rule p { condition: pe.is_dll() }`,
		`include "x.yar" rule r { condition: true }`,
		`rule r { strings: $h = { 4D 5A [0-2] ?? (90|00) } $r = /a.{0,9}b/is condition: #h > 1 or $r at 0 }`,
		`external filename rule r { condition: filename matches /\.exe$/ }`,
		`rule r { condition: for any i in (1..#a) : ( @a[i] < 10 ) }`,
		`/* unterminated`,
		`rule r { condition: "\x00\xff" }`,
	} {
		f.Add(s)
	}
	e := New(Options{CompileTimeout: 5 * time.Second})
	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 64<<10 {
			return
		}
		p, _, err := e.Compile(context.Background(), "fuzz", []byte(src))
		if err != nil {
			return
		}
		if _, err := p.ScanReader(context.Background(), bytes.NewReader([]byte(src)), File{Path: "f.txt"}); err != nil && p.RuleCount() == 0 {
			t.Fatal(err)
		}
	})
}

// fuzzRules is a fixed ruleset exercising text, hex, regex, counts, offsets
// and the hash/math modules.
const fuzzRules = `import "hash"
import "math"
rule text { strings: $a = "MZ" $b = "This program" nocase wide ascii condition: $a at 0 and $b }
rule hex { strings: $h = { 50 4B 03 04 [2-8] ( 14 | 0A ) ?? } condition: $h }
rule re { strings: $r = /[a-z0-9._%+-]{1,32}@[a-z0-9.-]{1,32}\.[a-z]{2,6}/ condition: #r > 2 }
rule ent { condition: filesize > 16 and math.entropy(0, filesize) > 7.5 }
rule md5 { condition: filesize < 64 and hash.md5(0, filesize) == "d41d8cd98f00b204e9800998ecf8427e" }
rule ext { condition: extension == "exe" and uint16(0) == 0x5A4D }
` + eicarRule

// FuzzScan: no input crashes the scanner, and a match never carries the
// input's bytes.
func FuzzScan(f *testing.F) {
	for _, s := range []string{"", eicar, "MZ\x90\x00This program cannot be run", "PK\x03\x04\x00\x00\x14\x00ab", "a@b.cc x@y.dd q@r.ee"} {
		f.Add([]byte(s))
	}
	p, _, err := New(Options{}).Compile(context.Background(), "fuzz", []byte(fuzzRules))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		ms, err := p.ScanReader(context.Background(), bytes.NewReader(data), File{Path: "C:\\x\\in.exe"})
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range ms {
			for _, id := range m.StringIDs {
				if len(id) == 0 || id[0] != '$' {
					t.Fatalf("string id %q", id)
				}
			}
		}
		if len(data) >= 12 {
			out, _ := json.Marshal(ms)
			if bytes.Contains(out, data) {
				t.Fatalf("match JSON contains the input: %s", out)
			}
		}
	})
}
