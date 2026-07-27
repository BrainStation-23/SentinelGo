// Package svcparse extracts the service/unit/app-pool name a service-control
// command targets, so EPM policy rules can be scoped to "only operate on
// ServiceFoo" instead of granting blanket control of sc.exe/systemctl/etc.
//
// This file has no build tags and performs no OS-specific I/O — it is pure
// string parsing over an executable path and an argument string, so every
// platform's patterns can be exercised from a single test binary on any host
// OS.
package svcparse

import "strings"

// ExtractServiceName inspects the executable being launched and its
// command-line arguments and returns the service/unit/app-pool name the
// command targets, if it recognizes the pattern. ok is false when
// executable/args do not match any known service-management CLI shape.
func ExtractServiceName(executable, args string) (string, bool) {
	tokens := strings.Fields(args)
	base := baseName(executable)
	baseLower := strings.ToLower(base)

	// Windows tool names are matched case-insensitively (sc.EXE == sc.exe).
	switch baseLower {
	case "sc.exe", "sc":
		return extractSC(tokens)
	case "net.exe", "net":
		return extractNet(tokens)
	case "iisreset.exe", "iisreset":
		return "w3svc", true // iisreset always targets the World Wide Web Publishing Service
	case "appcmd.exe", "appcmd":
		return extractAppcmd(tokens)
	}

	// Linux/macOS tool names are matched with exact case.
	switch base {
	case "systemctl":
		return extractSystemctl(tokens)
	case "service":
		return extractServiceCmd(tokens)
	case "launchctl":
		return extractLaunchctl(tokens)
	case "brew":
		return extractBrew(tokens)
	}

	return "", false
}

// baseName returns the final path segment of p, treating both '/' and '\' as
// separators regardless of the host OS this binary was built for.
//
// Deliberately not path/filepath.Base: filepath's separator handling is
// GOOS-dependent at compile time (a linux/darwin build only recognizes '/'),
// which would make Windows-style path test cases silently fail to strip the
// directory portion when the test binary runs on a non-Windows host.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// extractSC handles: sc.exe start|stop|query <name>.
func extractSC(tokens []string) (string, bool) {
	if len(tokens) < 2 {
		return "", false
	}
	switch strings.ToLower(tokens[0]) {
	case "start", "stop", "query":
		return tokens[1], true
	default:
		return "", false
	}
}

// extractNet handles: net start|stop <name>.
func extractNet(tokens []string) (string, bool) {
	if len(tokens) < 2 {
		return "", false
	}
	switch strings.ToLower(tokens[0]) {
	case "start", "stop":
		return tokens[1], true
	default:
		return "", false
	}
}

// extractAppcmd handles: appcmd.exe start|stop apppool /apppool.name:<name>.
func extractAppcmd(tokens []string) (string, bool) {
	if len(tokens) < 3 {
		return "", false
	}
	switch strings.ToLower(tokens[0]) {
	case "start", "stop":
	default:
		return "", false
	}
	if strings.ToLower(tokens[1]) != "apppool" {
		return "", false
	}
	const prefix = "/apppool.name:"
	for _, tok := range tokens[2:] {
		if len(tok) > len(prefix) && strings.EqualFold(tok[:len(prefix)], prefix) {
			return tok[len(prefix):], true
		}
	}
	return "", false
}

// extractSystemctl handles: systemctl start|stop|restart <unit>.
func extractSystemctl(tokens []string) (string, bool) {
	if len(tokens) < 2 {
		return "", false
	}
	switch tokens[0] {
	case "start", "stop", "restart":
		return tokens[1], true
	default:
		return "", false
	}
}

// extractServiceCmd handles: service <name> start|stop.
func extractServiceCmd(tokens []string) (string, bool) {
	if len(tokens) < 2 {
		return "", false
	}
	switch tokens[1] {
	case "start", "stop":
		return tokens[0], true
	default:
		return "", false
	}
}

// extractLaunchctl handles: launchctl start|stop <label> and
// launchctl kickstart [-k] <target>.
func extractLaunchctl(tokens []string) (string, bool) {
	if len(tokens) < 2 {
		return "", false
	}
	switch tokens[0] {
	case "start", "stop":
		return tokens[1], true
	case "kickstart":
		for _, tok := range tokens[1:] {
			if !strings.HasPrefix(tok, "-") {
				return tok, true
			}
		}
		return "", false
	default:
		return "", false
	}
}

// extractBrew handles: brew services start|stop <name>.
func extractBrew(tokens []string) (string, bool) {
	if len(tokens) < 3 {
		return "", false
	}
	if tokens[0] != "services" {
		return "", false
	}
	switch tokens[1] {
	case "start", "stop":
		return tokens[2], true
	default:
		return "", false
	}
}
