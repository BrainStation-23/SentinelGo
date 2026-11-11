package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/yara"
)

// eicar is the EICAR test string, the standard harmless "malware" sample.
const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

const eicarRule = `
rule eicar_test : test av {
  meta:
    author = "SentinelGo"
    severity = 3
  strings:
    $sig = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    $tail = "$H+H*"
  condition:
    $sig and $tail
}
`

func compile(t *testing.T, src string, o Options) (Program, []yara.SkippedRule) {
	t.Helper()
	p, skipped, err := New(o).Compile(context.Background(), "rs-1", []byte(src))
	if err != nil {
		t.Fatalf("Compile: %v (skipped %+v)", err, skipped)
	}
	return p, skipped
}

func scan(t *testing.T, p Program, data string, f File) []Match {
	t.Helper()
	m, err := p.ScanReader(context.Background(), strings.NewReader(data), f)
	if err != nil {
		t.Fatalf("ScanReader: %v", err)
	}
	return m
}

func TestEICARMatches(t *testing.T) {
	p, skipped := compile(t, eicarRule, Options{})
	if len(skipped) != 0 || p.RuleCount() != 1 {
		t.Fatalf("skipped %+v, rules %d", skipped, p.RuleCount())
	}
	got := scan(t, p, "junk "+eicar+" junk", File{Path: "/tmp/eicar.com"})
	if len(got) != 1 {
		t.Fatalf("matches = %+v, want one", got)
	}
	m := got[0]
	if m.Rule != "eicar_test" || m.Namespace != "rs-1" {
		t.Errorf("match = %+v", m)
	}
	if strings.Join(m.Tags, ",") != "test,av" {
		t.Errorf("tags = %v", m.Tags)
	}
	if strings.Join(m.StringIDs, ",") != "$sig,$tail" {
		t.Errorf("string ids = %v", m.StringIDs)
	}
	if m.Meta["author"] != "SentinelGo" {
		t.Errorf("meta = %v", m.Meta)
	}
	if got := scan(t, p, "clean file", File{}); len(got) != 0 {
		t.Errorf("clean file matched: %+v", got)
	}
}

// TestMatchCarriesNoBytes: nothing a scan returns, marshalled, contains the
// bytes the rule matched.
func TestMatchCarriesNoBytes(t *testing.T) {
	src := `rule secret { strings: $a = "TOPSECRET-4242" $h = { 54 4F 50 53 45 43 52 45 54 } $r = /TOP[A-Z]+-[0-9]{4}/ condition: any of them }`
	p, _ := compile(t, src, Options{})
	got := scan(t, p, "xx TOPSECRET-4242 yy", File{Path: "a.txt"})
	if len(got) != 1 {
		t.Fatalf("matches = %+v", got)
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"TOPSECRET", "4242", "xx", "yy"} {
		if strings.Contains(string(data), s) {
			t.Errorf("marshalled match contains %q: %s", s, data)
		}
	}
}

func TestPartialCompileSkipsUnsupportedModule(t *testing.T) {
	src := `import "pe"
import "hash"
rule needs_pe { condition: pe.number_of_sections > 1 }
rule uses_needs_pe { condition: needs_pe }
rule bad_syntax { condition: ( }
rule bad_semantic { condition: $nope }
rule hashed { condition: hash.md5(0, filesize) == "x" }
` + eicarRule
	p, skipped := compile(t, src, Options{})
	if p.RuleCount() != 2 {
		t.Errorf("rules = %d, want 2 (hashed, eicar_test)", p.RuleCount())
	}
	want := map[string]yara.SkippedRule{
		"needs_pe":      {Rule: "needs_pe", Line: 3, Reason: "unsupported_module:pe"},
		"uses_needs_pe": {Rule: "uses_needs_pe", Reason: "unsupported_module:pe"},
		"bad_syntax":    {Rule: "bad_syntax", Reason: ReasonSyntax}, // line: where the parser recovered
		"bad_semantic":  {Rule: "bad_semantic", Line: 6, Reason: ReasonSemantic},
	}
	if len(skipped) != len(want) {
		t.Fatalf("skipped = %+v", skipped)
	}
	for _, s := range skipped {
		w, ok := want[s.Rule]
		if !ok || s.Reason != w.Reason || (w.Line != 0 && s.Line != w.Line) {
			t.Errorf("skipped %+v, want %+v", s, w)
		}
	}
	if got := scan(t, p, eicar, File{}); len(got) != 1 || got[0].Rule != "eicar_test" {
		t.Errorf("matches = %+v", got)
	}
}

func TestExternals(t *testing.T) {
	src := `rule ext {
  condition:
    filename == "Invoice.PDF.exe" and extension == "exe" and
    filepath contains "Downloads" and filetype == "executable.pe"
}`
	p, _ := compile(t, src, Options{})
	f := File{Path: "/home/u/Downloads/Invoice.PDF.exe"}
	if got := scan(t, p, "MZ\x90\x00\x03\x00\x00\x00\x04\x00", f); len(got) != 1 {
		t.Errorf("sniffed pe: matches = %+v", got)
	}
	if got := scan(t, p, "plain text", f); len(got) != 0 {
		t.Errorf("text file matched as pe: %+v", got)
	}
	f.Type = "executable.pe"
	if got := scan(t, p, "plain text", f); len(got) != 1 {
		t.Errorf("given type: matches = %+v", got)
	}
}

// A ruleset that declares a standard external itself still compiles.
func TestSourceDeclaresExternal(t *testing.T) {
	p, _ := compile(t, "external filename\nrule r { condition: filename == \"x.bin\" }", Options{})
	if got := scan(t, p, "", File{Path: "x.bin"}); len(got) != 1 {
		t.Errorf("matches = %+v", got)
	}
}

func TestIncludeRejected(t *testing.T) {
	for _, src := range []string{
		"include \"other.yar\"\n" + eicarRule,
		eicarRule + "\n  include \"../../etc/passwd\"",
		"/* c */ include \"/etc/shadow\" " + eicarRule,
	} {
		_, _, err := New(Options{}).Compile(context.Background(), "x", []byte(src))
		if !errors.Is(err, ErrInclude) {
			t.Errorf("Compile(%q) = %v, want ErrInclude", src[:20], err)
		}
	}
	// "include" in a string, comment or rule body is not a directive.
	ok := `// include "a"
/* include "b" */
rule r { strings: $a = "include \"c\"" condition: $a }`
	compile(t, ok, Options{})
}

func TestCompileLimits(t *testing.T) {
	var b strings.Builder
	for i := range 3 {
		fmt.Fprintf(&b, "rule r%d { strings: $a = \"abc%dxyz\" condition: $a }\n", i, i)
	}
	if _, _, err := New(Options{MaxRules: 2}).Compile(context.Background(), "x", []byte(b.String())); !errors.Is(err, ErrTooManyRules) {
		t.Errorf("cap: err = %v, want ErrTooManyRules", err)
	}
	if _, _, err := New(Options{CompileTimeout: time.Nanosecond}).Compile(context.Background(), "x", []byte(b.String())); !errors.Is(err, ErrTimeout) {
		t.Errorf("timeout: err = %v, want ErrTimeout", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := New(Options{}).Compile(ctx, "x", []byte(b.String())); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: err = %v", err)
	}
	if _, _, err := New(Options{}).Compile(context.Background(), "x", []byte("rule bad { condition: ( }")); !errors.Is(err, ErrNoRules) {
		t.Errorf("nothing compiles: err = %v, want ErrNoRules", err)
	}
	big := make([]byte, yara.MaxRulesetBytes+1)
	if _, _, err := New(Options{}).Compile(context.Background(), "x", big); err == nil {
		t.Error("oversized ruleset compiled")
	}
}

func TestScanStopsAtSize(t *testing.T) {
	p, _ := compile(t, eicarRule, Options{})
	data := strings.Repeat("a", 100) + eicar
	if got := scan(t, p, data, File{Size: 100}); len(got) != 0 {
		t.Errorf("matched past Size: %+v", got)
	}
	if got := scan(t, p, data, File{Size: int64(len(data))}); len(got) != 1 {
		t.Errorf("matches = %+v", got)
	}
}

func TestScanCancelled(t *testing.T) {
	p, _ := compile(t, eicarRule, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.ScanReader(ctx, strings.NewReader(eicar), File{}); err == nil {
		t.Error("cancelled scan succeeded")
	}
}

func TestConcurrentScans(t *testing.T) {
	p, _ := compile(t, eicarRule, Options{})
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			data := strings.Repeat("x", i*1000)
			if i%2 == 0 {
				data += eicar
			}
			m, err := p.ScanReader(context.Background(), strings.NewReader(data), File{})
			if err != nil || len(m) != 1-i%2 {
				t.Errorf("scan %d: %v %+v", i, err, m)
			}
		})
	}
	wg.Wait()
}

func TestEngineVersion(t *testing.T) {
	if v := New(Options{}).Version(); v != strings.TrimPrefix(pinnedVersion, "v") {
		t.Errorf("Version() = %q, want %q", v, pinnedVersion)
	}
}
