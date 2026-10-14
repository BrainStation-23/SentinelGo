package shared

import (
	"reflect"
	"testing"
	"time"
)

const plistSample = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>name</key><string>Backup &amp; Restore</string>
	<key>count</key><integer>-3</integer>
	<key>ratio</key><real>1.5</real>
	<key>on</key><true/>
	<key>off</key><false/>
	<key>when</key><date>2026-10-14T01:00:00Z</date>
	<key>blob</key><data>AAEC</data>
	<key>empty</key><dict/>
	<key>list</key><array><integer>1</integer><string>two</string><array/></array>
</dict>
</plist>`

func TestDecodePlistXML(t *testing.T) {
	v, err := DecodePlistXML([]byte(plistSample))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"name":  "Backup & Restore",
		"count": int64(-3),
		"ratio": 1.5,
		"on":    true,
		"off":   false,
		"when":  time.Date(2026, 10, 14, 1, 0, 0, 0, time.UTC),
		"blob":  "AAEC",
		"empty": map[string]any{},
		"list":  []any{int64(1), "two", []any(nil)},
	}
	if !reflect.DeepEqual(v, want) {
		t.Errorf("got  %#v\nwant %#v", v, want)
	}
}

func TestDecodePlistXML_Errors(t *testing.T) {
	for _, bad := range []string{"", "<plist><dict><key>a</key><unknown>1</unknown></dict></plist>", "<plist><integer>x</integer></plist>"} {
		if _, err := DecodePlistXML([]byte(bad)); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func TestPlistFromOutput(t *testing.T) {
	v, ok := PlistFromOutput("accountPolicyData:\n<?xml version=\"1.0\"?>\n<plist version=\"1.0\"><dict><key>a</key><integer>1</integer></dict></plist>\n")
	if !ok || v.(map[string]any)["a"] != int64(1) {
		t.Errorf("v=%v ok=%v", v, ok)
	}
	if _, ok := PlistFromOutput("No such key: accountPolicyData"); ok {
		t.Error("output without a plist should give ok=false")
	}
}

func TestPlistNumberAndBool(t *testing.T) {
	for _, c := range []struct {
		v    any
		want float64
		ok   bool
	}{{int64(7), 7, true}, {2.5, 2.5, true}, {" 9 ", 9, true}, {"x", 0, false}, {nil, 0, false}} {
		got, ok := PlistNumber(c.v)
		if got != c.want || ok != c.ok {
			t.Errorf("PlistNumber(%#v) = %v, %v", c.v, got, ok)
		}
	}
	for _, c := range []struct {
		v      any
		want   bool
		wantOK bool
	}{{true, true, true}, {int64(0), false, true}, {1.0, true, true}, {"YES", true, true}, {"0", false, true}, {"maybe", false, false}, {nil, false, false}} {
		got, ok := PlistBool(c.v)
		if got != c.want || ok != c.wantOK {
			t.Errorf("PlistBool(%#v) = %v, %v", c.v, got, ok)
		}
	}
}
