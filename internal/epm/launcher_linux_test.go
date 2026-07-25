//go:build linux

package epm

import (
	"reflect"
	"testing"
)

func TestParseEnviron_TypicalEntries(t *testing.T) {
	data := []byte("DISPLAY=:0\x00HOME=/home/alice\x00PATH=/usr/bin\x00")
	got := parseEnviron(data)
	want := map[string]string{
		"DISPLAY": ":0",
		"HOME":    "/home/alice",
		"PATH":    "/usr/bin",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseEnviron = %v, want %v", got, want)
	}
}

func TestParseEnviron_EmptyInput(t *testing.T) {
	got := parseEnviron(nil)
	if len(got) != 0 {
		t.Errorf("parseEnviron(nil) = %v, want empty map", got)
	}
}

func TestParseEnviron_SkipsMalformedEntries(t *testing.T) {
	data := []byte("VALID=1\x00NOVALUE\x00\x00ANOTHER=2\x00")
	got := parseEnviron(data)
	want := map[string]string{"VALID": "1", "ANOTHER": "2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseEnviron = %v, want %v", got, want)
	}
}

func TestBuildLaunchEnviron_IncludesSessionVarsAndIdentity(t *testing.T) {
	sessionEnv := map[string]string{
		"DISPLAY":    ":0",
		"XAUTHORITY": "/home/alice/.Xauthority",
		"HOME":       "/home/alice",
	}
	env := buildLaunchEnviron(sessionEnv, "alice")

	want := map[string]string{
		"DISPLAY":    ":0",
		"XAUTHORITY": "/home/alice/.Xauthority",
		"HOME":       "/home/alice",
		"USER":       "alice",
		"LOGNAME":    "alice",
	}
	got := map[string]string{}
	for _, kv := range env {
		key, value, ok := splitKV(kv)
		if ok {
			got[key] = value
		}
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("env[%q] = %q, want %q", k, got[k], v)
		}
	}
}

func splitKV(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}
