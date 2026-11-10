package packages

import "testing"

// The parsers read files in user-writable folders: any input must return
// without panicking, and whatever they return must be usable as-is.

func FuzzParsePackageJSON(f *testing.F) {
	f.Add([]byte(`{"name":"@scope/x","version":"1.0.0"}`))
	f.Add([]byte(`{"name":null}`))
	f.Add([]byte(`[`))
	f.Fuzz(func(t *testing.T, data []byte) {
		name, version, ok := parsePackageJSON(data)
		if ok && (name == "" || version == "") {
			t.Fatalf("ok with empty field: %q %q", name, version)
		}
	})
}

func FuzzParseCoreMetadata(f *testing.F) {
	f.Add([]byte("Metadata-Version: 2.1\nName: requests\nVersion: 2.32.3\n\nbody"))
	f.Add([]byte("Name:\nVersion:\n"))
	f.Add([]byte(":::\n\n\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		name, version, ok := parseCoreMetadata(data)
		if ok && (name == "" || version == "") {
			t.Fatalf("ok with empty field: %q %q", name, version)
		}
	})
}

func FuzzParseComposerInstalled(f *testing.F) {
	f.Add([]byte(`[{"name":"a/b","version":"v1"}]`))
	f.Add([]byte(`{"packages":[{"name":"a/b","version":"1.0"}]}`))
	f.Add([]byte(`{"packages":[null]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, p := range parseComposerInstalled(data) {
			if p.Name == "" || p.Version == "" {
				t.Fatalf("empty field: %+v", p)
			}
		}
	})
}
