package policy

// At-rest classification (#331 part 2): the agent scans the files in the
// user folders in scope ahead of time, in the background, so a sensitive
// file is known as sensitive before it moves. Process taint and taint blocks then take the stored verdict
// instead of scanning when a program opens or copies the file. Windows only
// for now; off unless the bundle turns it on.

import (
	"encoding/json"
	"fmt"
	"strings"
)

// AtRest is modules.files.at_rest.
type AtRest struct {
	Enabled bool `json:"enabled"`
	// Folders are the folders in scope, by GOOS; "~" means every user
	// profile, %VAR% and "*" (one path segment) are expanded. None for an
	// OS means the default folders (DefaultAtRestFolders).
	Folders map[string][]string `json:"folders"`
	// Exclude are folders (or files) never classified, by GOOS, in the
	// same form.
	Exclude map[string][]string `json:"exclude"`
	// MaxCPUPercent bounds the classification's CPU use, as a percentage
	// of one core.
	MaxCPUPercent int `json:"max_cpu_percent"`
	// SkipOnBattery pauses classification while the device runs on
	// battery. Absent means true.
	SkipOnBattery *bool `json:"skip_on_battery"`
	// RescanHours is how often the folders are walked again in full, to
	// catch what the change journal missed (unchanged files are skipped
	// without being read).
	RescanHours int `json:"rescan_hours"`

	// DecodeError is why the block couldn't be read; classification is
	// then off.
	DecodeError string `json:"-"`
}

// At-rest limits.
const (
	DefaultAtRestCPUPercent   = 10
	MinAtRestCPUPercent       = 1
	MaxAtRestCPUPercent       = 50
	DefaultAtRestRescanHours  = 24
	MinAtRestRescanHours      = 6
	MaxAtRestRescanHours      = 168
	maxAtRestFolders          = 64
	maxAtRestExcludes         = 256
	maxAtRestFolderPathLength = 1024
)

// DefaultAtRestFolders are the folders classified when the bundle lists
// none for an OS: where users keep and receive documents, and the cloud
// sync folders under their profiles.
var DefaultAtRestFolders = map[string][]string{
	"windows": {
		`~\Documents`, `~\Desktop`, `~\Downloads`,
		`~\OneDrive*`, `~\Dropbox*`, `~\Box`, `~\Google Drive`, `~\iCloudDrive`,
	},
}

// UnmarshalJSON never fails: an unreadable block turns classification off
// with DecodeError set, so it can't turn file DLP off.
func (a *AtRest) UnmarshalJSON(data []byte) error {
	type plain AtRest
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		*a = AtRest{DecodeError: fmt.Sprintf("modules.files.at_rest: %v", err)}
		return nil
	}
	*a = AtRest(p)
	return nil
}

func (a *AtRest) normalize() {
	if a.DecodeError != "" {
		a.Enabled = false
	}
	if a.MaxCPUPercent <= 0 {
		a.MaxCPUPercent = DefaultAtRestCPUPercent
	}
	a.MaxCPUPercent = min(max(a.MaxCPUPercent, MinAtRestCPUPercent), MaxAtRestCPUPercent)
	if a.RescanHours <= 0 {
		a.RescanHours = DefaultAtRestRescanHours
	}
	a.RescanHours = min(max(a.RescanHours, MinAtRestRescanHours), MaxAtRestRescanHours)
	a.Folders = cleanPathLists(a.Folders, maxAtRestFolders)
	a.Exclude = cleanPathLists(a.Exclude, maxAtRestExcludes)
}

// cleanPathLists drops empty and over-long entries and duplicates, and
// bounds each OS's list.
func cleanPathLists(in map[string][]string, limit int) map[string][]string {
	if len(in) == 0 {
		return in
	}
	out := make(map[string][]string, len(in))
	for goos, paths := range in {
		var list []string
		seen := map[string]bool{}
		for _, p := range paths {
			p = strings.TrimSpace(p)
			key := strings.ToLower(p)
			if p == "" || len(p) > maxAtRestFolderPathLength || seen[key] {
				continue
			}
			seen[key] = true
			list = append(list, p)
			if len(list) == limit {
				break
			}
		}
		out[goos] = list
	}
	return out
}

// PausesOnBattery reports whether classification pauses on battery.
func (a AtRest) PausesOnBattery() bool { return a.SkipOnBattery == nil || *a.SkipOnBattery }

// FoldersFor returns the folders in scope for goos: the bundle's, or the
// defaults when it lists none.
func (a AtRest) FoldersFor(goos string) []string {
	if f := a.Folders[goos]; len(f) > 0 {
		return f
	}
	return DefaultAtRestFolders[goos]
}

// WantsAtRest reports whether m asks for at-rest classification: the
// module and the block are on. Its verdicts are only used by process taint
// and taint blocks, so ClassifiesAtRest also needs one of those.
func (m FilesModule) WantsAtRest() bool {
	return m.Enabled && m.DecodeError == "" && m.AtRest.Enabled
}

// ClassifiesAtRest reports whether m turns at-rest classification on for
// goos and something uses its verdicts: process taint, or taint blocks.
func (m FilesModule) ClassifiesAtRest(goos string) bool {
	return m.WantsAtRest() && (m.CopyCorrelation.ProcessTaint || m.TaintsNetwork(goos))
}
