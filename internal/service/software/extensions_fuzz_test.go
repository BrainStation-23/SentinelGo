package software

// Fuzz targets for browser-extension metadata parsing. manifest.json and
// _locales/*/messages.json are written by the extension itself, so their
// contents are attacker-controlled: parsing must never panic and must always
// produce a usable name.
//
// The seed corpus below runs as an ordinary unit test under `go test ./...`.
// To actually fuzz one target:
//
//	go test -run='^$' -fuzz='^FuzzParseExtensionManifest$' -fuzztime=1m ./internal/service/software/

import (
	"strings"
	"testing"
)

var manifestSeeds = []string{
	`{"name":"uBlock Origin","version":"1.58.0","manifest_version":3}`,
	`{"name":"__MSG_appName__","version":"2.0","default_locale":"en"}`,
	`{"name":"","version":"1"}`,
	`{"name":123,"version":["1"]}`,
	`{"name":null,"version":null}`,
	`{"version":"1.0"}`,
	"\xef\xbb\xbf{\"name\":\"BOM prefixed\"}",
	`{"name":"truncated`,
	``,
	`null`,
	`[]`,
	`{"name":"a","name":"b"}`,
	`{"name":"` + strings.Repeat("x", 1<<16) + `"}`,
	strings.Repeat(`{"a":`, 2000) + strings.Repeat(`}`, 2000),
}

func FuzzParseExtensionManifest(f *testing.F) {
	for _, s := range manifestSeeds {
		f.Add([]byte(s), "fallback-id")
	}
	f.Add([]byte(`{"name":""}`), "")

	f.Fuzz(func(t *testing.T, data []byte, fallbackID string) {
		name, _ := parseExtensionManifest(data, fallbackID)
		if fallbackID != "" && name == "" {
			t.Fatalf("parseExtensionManifest(%q, %q) returned an empty name", data, fallbackID)
		}
	})
}

func FuzzParseLocaleMessage(f *testing.F) {
	f.Add([]byte(`{"appName":{"message":"Password Manager","description":"x"}}`), "appName")
	f.Add([]byte(`{"g":{"message":"Hi $U$","placeholders":{"u":{"content":"$1"}}}}`), "g")
	f.Add([]byte(`{"appName":{"message":42}}`), "appName")
	f.Add([]byte(`{"appName":"not an object"}`), "appName")
	f.Add([]byte(`{"appName":null}`), "appName")
	f.Add([]byte(`{"appName":[]}`), "appName")
	f.Add([]byte(`[]`), "appName")
	f.Add([]byte(``), "")
	f.Add([]byte(`{"":{"message":"empty key"}}`), "")
	f.Add([]byte(`{"k":{"message":"`+strings.Repeat("y", 1<<16)+`"}}`), "k")

	f.Fuzz(func(t *testing.T, data []byte, key string) {
		_ = parseLocaleMessage(data, key)
	})
}

// FuzzNormalizeI18nKey only checks that arbitrary keys don't panic and that
// strings without the "__MSG_" / "__" markers pass through unchanged. It is
// intentionally not idempotent ("__MSG___MSG_x____" strips one layer per call),
// which is harmless because callers apply it exactly once.
func FuzzNormalizeI18nKey(f *testing.F) {
	for _, s := range []string{"__MSG_appName__", "__MSG___", "__MSG_", "__", "", "plain", "__MSG___MSG_x____", "__MSG_\x00__"} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, key string) {
		got := normalizeI18nKey(key)
		if !strings.HasPrefix(key, "__MSG_") && !strings.HasSuffix(key, "__") && got != key {
			t.Fatalf("normalizeI18nKey(%q) = %q, want it unchanged", key, got)
		}
	})
}
