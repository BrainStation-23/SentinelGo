//go:build windows

package software

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// fileTimeToUnixOffset is the number of 100-nanosecond intervals between the
// Windows FILETIME epoch (1601-01-01 UTC) and the Unix epoch (1970-01-01 UTC).
const fileTimeToUnixOffset = 116444736000000000

// userAssistLastRunOffset is the byte offset of the 8-byte little-endian FILETIME
// holding the last-execution time in the modern (Windows 7+) UserAssist value
// structure. Values shorter than offset+8 use a legacy layout without it.
const userAssistLastRunOffset = 60

// userAssistQuery dumps every UserAssist "Count" value (executable GUID) for all
// real user hives under HKEY_USERS. The agent typically runs as SYSTEM, so it must
// read HKEY_USERS rather than HKCU (which would be the SYSTEM profile). Each value
// name is ROT13-encoded and each value's data is a binary blob; both are returned
// raw (name as-is, data base64-encoded) and decoded in Go so the logic is testable.
const userAssistQuery = `$ErrorActionPreference='SilentlyContinue';$out=@();Get-ChildItem 'Registry::HKEY_USERS' | Where-Object {$_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$'} | ForEach-Object {$k="Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count";$rk=Get-Item -LiteralPath $k -ErrorAction SilentlyContinue;if($rk){foreach($n in $rk.GetValueNames()){$d=$rk.GetValue($n);if($d -is [byte[]]){$out+=[PSCustomObject]@{Name=$n;Data=[Convert]::ToBase64String($d)}}}}};$out | ConvertTo-Json -Compress`

// userAssistRecord is one raw UserAssist Count value emitted by userAssistQuery.
type userAssistRecord struct {
	Name string `json:"Name"` // ROT13-encoded launch path
	Data string `json:"Data"` // base64-encoded value bytes
}

// lastOpenedEntry is a decoded UserAssist launch record: a lowercased executable
// path and the time it was last run.
type lastOpenedEntry struct {
	Path    string
	LastRun time.Time
}

// getWindowsLastOpened returns decoded UserAssist launch records across all real
// user hives. It is best-effort: any failure (query error, timeout, no data)
// yields nil so that last-opened enrichment can never disrupt the install/
// uninstall reconciliation in platformSoftware.
func getWindowsLastOpened() []lastOpenedEntry {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", userAssistQuery)
	output, err := cmd.Output()
	if err != nil {
		log.Printf("software: UserAssist query failed: %v", err)
		return nil
	}
	return parseUserAssist(output, knownFolderRoots())
}

// parseUserAssist decodes the raw UserAssist dump into launch records, resolving
// KNOWNFOLDERID GUID prefixes via roots. Entries that cannot be resolved to an
// absolute path, that are too short to carry a timestamp, or that have never been
// run (zero FILETIME) are skipped.
func parseUserAssist(output []byte, roots map[string]string) []lastOpenedEntry {
	if len(output) == 0 {
		return nil
	}
	var records []userAssistRecord
	if err := json.Unmarshal(output, &records); err != nil {
		var single userAssistRecord
		if err2 := json.Unmarshal(output, &single); err2 != nil {
			return nil
		}
		records = []userAssistRecord{single}
	}

	var entries []lastOpenedEntry
	for _, rec := range records {
		path := normalizeUserAssistPath(rot13(rec.Name), roots)
		if path == "" {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(rec.Data)
		if err != nil || len(data) < userAssistLastRunOffset+8 {
			continue
		}
		ft := binary.LittleEndian.Uint64(data[userAssistLastRunOffset : userAssistLastRunOffset+8])
		if ft <= fileTimeToUnixOffset {
			continue // never run, or pre-1970 — not a usable last-opened time.
		}
		entries = append(entries, lastOpenedEntry{
			Path:    strings.ToLower(path),
			LastRun: fileTimeToTime(ft),
		})
	}
	return entries
}

// applyLastOpened sets LastOpened on each program whose InstallLocation contains a
// UserAssist-tracked executable, using the most recent matching launch. Programs
// without an install location, or with no matching launch, are left untouched.
func applyLastOpened(software []SoftwareInfo, entries []lastOpenedEntry) {
	if len(entries) == 0 {
		return
	}
	for i := range software {
		loc := strings.ToLower(strings.TrimRight(software[i].FilePath, `\`))
		if loc == "" {
			continue
		}
		prefix := loc + `\`
		var best time.Time
		for _, e := range entries {
			if strings.HasPrefix(e.Path, prefix) && e.LastRun.After(best) {
				best = e.LastRun
			}
		}
		if !best.IsZero() {
			software[i].LastOpened = best.UTC().Format(time.RFC3339)
		}
	}
}

// rot13 decodes a ROT13-obfuscated UserAssist value name. Only ASCII letters are
// transformed; digits, separators, and GUID braces pass through unchanged.
func rot13(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			b[i] = 'A' + (c-'A'+13)%26
		}
	}
	return string(b)
}

// fileTimeToTime converts a Windows FILETIME (100-ns intervals since 1601) to a
// UTC time.Time. Callers must ensure ft > fileTimeToUnixOffset.
func fileTimeToTime(ft uint64) time.Time {
	return time.Unix(0, int64(ft-fileTimeToUnixOffset)*100).UTC()
}

// knownFolderRoots maps the UserAssist KNOWNFOLDERID GUID prefixes we resolve to
// absolute paths, sourced from the environment where possible so they are correct
// regardless of drive letter or localized folder names.
func knownFolderRoots() map[string]string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	pf86 := os.Getenv("ProgramFiles(x86)")
	if pf86 == "" {
		pf86 = `C:\Program Files (x86)`
	}
	windir := os.Getenv("windir")
	if windir == "" {
		windir = `C:\Windows`
	}
	return map[string]string{
		"{6d809377-6af0-444b-8957-a3773f02200e}": pf,                   // ProgramFilesX64
		"{905e63b6-c1bf-494e-b29c-65b732d3d21a}": pf,                   // ProgramFiles
		"{7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e}": pf86,                 // ProgramFilesX86
		"{f38bf404-1d43-42f2-9305-67de0b28fc23}": windir,               // Windows
		"{1ac14e77-02e7-4e5d-b744-2eb1ae5198b7}": windir + `\System32`, // System
	}
}

// normalizeUserAssistPath resolves a leading KNOWNFOLDERID GUID to a real path.
// An already-absolute path is returned unchanged; a path whose GUID prefix is not
// one we resolve returns "" (it cannot be matched to an install location).
func normalizeUserAssistPath(path string, roots map[string]string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if path[0] != '{' {
		return path
	}
	end := strings.IndexByte(path, '}')
	if end < 0 {
		return ""
	}
	root, ok := roots[strings.ToLower(path[:end+1])]
	if !ok {
		return ""
	}
	return root + `\` + strings.TrimLeft(path[end+1:], `\`)
}
