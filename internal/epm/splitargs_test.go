package epm

import (
	"reflect"
	"testing"
)

func TestSplitArgs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		// ── empty / trivial ────────────────────────────────────────────────
		{
			name:  "empty string returns nil",
			input: "",
			want:  nil,
		},
		{
			name:  "single plain token",
			input: "hello",
			want:  []string{"hello"},
		},
		{
			name:  "multiple plain tokens separated by spaces",
			input: "foo bar baz",
			want:  []string{"foo", "bar", "baz"},
		},
		{
			name:  "leading and trailing whitespace is ignored",
			input: "  foo   bar  ",
			want:  []string{"foo", "bar"},
		},
		{
			name:  "tab and newline are also whitespace separators",
			input: "foo\tbar\nbaz",
			want:  []string{"foo", "bar", "baz"},
		},

		// ── double-quoted groups ────────────────────────────────────────────
		{
			name:  "double-quoted token with spaces",
			input: `"hello world"`,
			want:  []string{"hello world"},
		},
		{
			name:  "flag followed by double-quoted path with spaces",
			input: `--msg "hello world" --flag`,
			want:  []string{"--msg", "hello world", "--flag"},
		},
		{
			name:  "double-quoted path that looks like a Windows path",
			input: `"C:\Program Files\App\tool.exe"`,
			want:  []string{`C:\Program Files\App\tool.exe`},
		},
		{
			name:  "install arg with double-quoted msi path",
			input: `/i "C:\Users\jsmith\Downloads\my tool.msi" /qn`,
			want:  []string{"/i", `C:\Users\jsmith\Downloads\my tool.msi`, "/qn"},
		},
		{
			name:  `escaped double-quote inside double-quoted group`,
			input: `"say \"hi\""`,
			want:  []string{`say "hi"`},
		},
		{
			name:  `escaped backslash inside double-quoted group`,
			input: `"C:\\Users\\foo"`,
			want:  []string{`C:\Users\foo`},
		},
		{
			name:  "unrecognised backslash-escape inside double quotes is kept literally",
			input: `"line\nbreak"`,
			want:  []string{`line\nbreak`},
		},
		{
			name:  "adjacent double-quoted tokens merge into one token",
			input: `"foo""bar"`,
			want:  []string{"foobar"},
		},

		// ── single-quoted groups ────────────────────────────────────────────
		{
			name:  "single-quoted token with spaces",
			input: `'hello world'`,
			want:  []string{"hello world"},
		},
		{
			name:  "single-quoted path on Linux",
			input: `'/opt/my tool/run.sh' --yes`,
			want:  []string{"/opt/my tool/run.sh", "--yes"},
		},
		{
			name:  "backslash inside single quotes is literal (no escaping)",
			input: `'C:\Program Files\tool.exe'`,
			want:  []string{`C:\Program Files\tool.exe`},
		},
		{
			name:  "POSIX quoting trick for single-quote inside single-quoted group",
			input: `'it'\''s fine'`,
			want:  []string{"it's fine"},
		},

		// ── unquoted backslash ──────────────────────────────────────────────
		{
			name:  "unquoted backslash escapes the following space",
			input: `/opt/my\ tool/run.sh --yes`,
			want:  []string{"/opt/my tool/run.sh", "--yes"},
		},
		{
			name:  "unquoted backslash escapes any character",
			input: `foo\ bar`,
			want:  []string{"foo bar"},
		},

		// ── mixed quoting ───────────────────────────────────────────────────
		{
			name:  "double-quoted segment adjacent to unquoted segment",
			input: `pre"fix suffix"`,
			want:  []string{"prefix suffix"},
		},
		{
			name:  "single-quoted segment adjacent to unquoted segment",
			input: `pre'fix and more'`,
			want:  []string{"prefix and more"},
		},
		{
			name:  "dpkg install with single-quoted deb path containing spaces",
			input: `-i '/tmp/my packages/tool.deb'`,
			want:  []string{"-i", "/tmp/my packages/tool.deb"},
		},
		{
			name:  "pip install requirements file with space in path",
			input: `-r '/home/user/my project/requirements.txt'`,
			want:  []string{"-r", "/home/user/my project/requirements.txt"},
		},

		// ── error / fallback ────────────────────────────────────────────────
		// An unterminated quote falls back to whitespace splitting (the
		// pre-fix behaviour) rather than returning nil, so a malformed
		// argument string still produces a usable (if inaccurate) token list.
		{
			name:  "unterminated double quote falls back to whitespace split",
			input: `foo "bar baz`,
			want:  []string{"foo", `"bar`, "baz"},
		},
		{
			name:  "unterminated single quote falls back to whitespace split",
			input: `foo 'bar baz`,
			want:  []string{"foo", `'bar`, "baz"},
		},
		{
			name:  "trailing bare backslash falls back to whitespace split",
			input: `foo bar\`,
			want:  []string{"foo", `bar\`},
		},

		// ── real EPM command-line examples ──────────────────────────────────
		{
			name:  "msiexec silent install with quoted msi path",
			input: `/i "C:\Users\jsmith\Downloads\tool.msi" /qn`,
			want:  []string{"/i", `C:\Users\jsmith\Downloads\tool.msi`, "/qn"},
		},
		{
			name:  "dpkg install with plain path (no spaces)",
			input: "-i /tmp/tool.deb",
			want:  []string{"-i", "/tmp/tool.deb"},
		},
		{
			name:  "node script with --prod flag",
			input: "--prod",
			want:  []string{"--prod"},
		},
		{
			name:  "appcmd start apppool flag",
			input: "start apppool /apppool.name:MyPool",
			want:  []string{"start", "apppool", "/apppool.name:MyPool"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitArgs(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitArgs(%q)\n got  %#v\n want %#v", tt.input, got, tt.want)
			}
		})
	}
}

// TestShellSplitErrorCases tests the internal shellSplit function directly to
// ensure each error path returns a non-nil error and not a silent empty slice.
func TestShellSplitErrorCases(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"unterminated double quote", `"hello`},
		{"unterminated single quote", `'hello`},
		{"trailing backslash", `foo\`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := shellSplit(tc.input)
			if err == nil {
				t.Errorf("shellSplit(%q): expected error, got nil", tc.input)
			}
		})
	}
}

// TestWhitespaceFields ensures the fallback splitter matches the behaviour of
// the old strings.Fields-based splitArgs so a regression in the fallback path
// cannot silently change anything.
func TestWhitespaceFields(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"foo", []string{"foo"}},
		{"foo bar baz", []string{"foo", "bar", "baz"}},
		{"  foo   bar  ", []string{"foo", "bar"}},
		{`"foo bar"`, []string{`"foo`, `bar"`}}, // no quote handling
	}

	for _, tt := range tests {
		got := whitespaceFields(tt.input)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("whitespaceFields(%q)\n got  %#v\n want %#v", tt.input, got, tt.want)
		}
	}
}
