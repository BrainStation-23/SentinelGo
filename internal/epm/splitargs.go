// Package epm — this file provides splitArgs, a shell-word splitter that
// handles single-quoted and double-quoted tokens so arguments containing
// spaces (e.g. paths like "/opt/my tools/run.sh" or Windows-style
// "C:\Program Files\tool.exe") survive the round-trip from the EPM client
// to the elevated process launcher.
//
// This file has no build tag: the implementation is pure Go with no OS-specific
// calls, so it compiles and is tested on every platform (including Windows
// developer machines), even though it is only called on Linux and Darwin via
// socket_linux.go and socket_darwin.go.
package epm

import "fmt"

// splitArgs splits a shell-style argument string into individual tokens,
// respecting single-quoted ('…') and double-quoted ("…") groups so that
// spaces inside quotes are not treated as token separators.
//
// Rules (POSIX-shell subset, sufficient for EPM command-line construction):
//   - Unquoted whitespace (space, tab, newline, CR) separates tokens.
//   - Single quotes preserve everything literally — no escape sequences
//     inside single quotes.
//   - Double quotes preserve everything except \" (escaped double-quote)
//     and \\ (escaped backslash). No other backslash sequences are
//     interpreted inside double quotes.
//   - Outside quotes, a backslash escapes the next character literally.
//   - An unterminated quote or a trailing bare backslash returns an error;
//     callers fall back to simple whitespace splitting so a malformed
//     argument string is never silently dropped.
//
// Examples:
//
//	`/opt/my\ tool/run.sh --yes`     → ["/opt/my tool/run.sh", "--yes"]
//	`"/opt/my tool/run.sh" --yes`    → ["/opt/my tool/run.sh", "--yes"]
//	`--msg "hello world" --flag`     → ["--msg", "hello world", "--flag"]
//	`'it'\''s fine'`                 → ["it's fine"]  (POSIX quoting trick)
//	`-i "/tmp/my app.deb"`           → ["-i", "/tmp/my app.deb"]
func splitArgs(commandLine string) []string {
	if commandLine == "" {
		return nil
	}
	tokens, err := shellSplit(commandLine)
	if err != nil {
		// Unterminated quote or trailing backslash: fall back to the previous
		// whitespace-only behaviour so a malformed string still produces
		// something rather than an empty launch argument list.
		return whitespaceFields(commandLine)
	}
	return tokens
}

// shellSplit is the core parser. Returns an error on unterminated quotes or a
// trailing bare backslash.
func shellSplit(s string) ([]string, error) {
	var tokens []string
	var cur []byte
	inToken := false

	i := 0
	for i < len(s) {
		ch := s[i]

		switch ch {
		case '\'':
			// Single-quoted group: everything inside is literal.
			inToken = true
			i++ // consume opening '
			for i < len(s) && s[i] != '\'' {
				cur = append(cur, s[i])
				i++
			}
			if i >= len(s) {
				return nil, fmt.Errorf("splitArgs: unterminated single quote in %q", s)
			}
			i++ // consume closing '

		case '"':
			// Double-quoted group: \" and \\ are escape sequences; everything
			// else (including single backslashes not followed by " or \) is
			// copied literally, matching POSIX double-quote semantics.
			inToken = true
			i++ // consume opening "
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
					cur = append(cur, s[i+1])
					i += 2
				} else {
					cur = append(cur, s[i])
					i++
				}
			}
			if i >= len(s) {
				return nil, fmt.Errorf("splitArgs: unterminated double quote in %q", s)
			}
			i++ // consume closing "

		case '\\':
			// Unquoted backslash: the next character is literal.
			if i+1 >= len(s) {
				return nil, fmt.Errorf("splitArgs: trailing backslash in %q", s)
			}
			inToken = true
			cur = append(cur, s[i+1])
			i += 2

		case ' ', '\t', '\n', '\r':
			// Unquoted whitespace: flush current token (if any).
			if inToken {
				tokens = append(tokens, string(cur))
				cur = cur[:0]
				inToken = false
			}
			i++

		default:
			inToken = true
			cur = append(cur, ch)
			i++
		}
	}

	if inToken {
		tokens = append(tokens, string(cur))
	}
	return tokens, nil
}

// whitespaceFields is the pre-fix fallback: split on whitespace only, no
// quote handling. Used when shellSplit returns an error so a malformed
// argument string is never silently discarded.
func whitespaceFields(s string) []string {
	var tokens []string
	start := -1
	for i := 0; i <= len(s); i++ {
		isWS := i == len(s) || s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r'
		if !isWS && start < 0 {
			start = i
		} else if isWS && start >= 0 {
			tokens = append(tokens, s[start:i])
			start = -1
		}
	}
	return tokens
}
