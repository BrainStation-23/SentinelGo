//go:build windows && (amd64 || arm64)

package netctl

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"

	"sentinelgo/internal/wfp"
)

// netSublayer holds the network control filters, apart from the upload
// proxy's direct block, so each swaps its own filters.
var netSublayer = windows.GUID{Data1: 0x93f343bf, Data2: 0x012b, Data3: 0x460c, Data4: [8]byte{0x81, 0x12, 0x56, 0xca, 0x75, 0x1d, 0xe3, 0x8f}}

const netSublayerWeight = 0x7000

// Filter weights in the sublayer: the allowed destinations beat the block.
const (
	weightAllow = 15
	weightBlock = 1
)

// loopback is always reachable: blocking an app's local IPC breaks it in
// ways that have nothing to do with leaving the device.
var loopback = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}

var platformOpen = func() (Ruleset, error) { return openWFP() }

type wfpRuleset struct {
	s   *wfp.Session
	ids []uint64
}

func openWFP() (*wfpRuleset, error) {
	s, err := wfp.Open("SentinelGo network controls")
	if err != nil {
		return nil, err
	}
	if err := s.Transaction(func() error {
		return s.AddSublayer(netSublayer, "SentinelGo network controls", netSublayerWeight)
	}); err != nil {
		_ = s.Close()
		return nil, err
	}
	return &wfpRuleset{s: s}, nil
}

// Set swaps the filters in one transaction. Per address family: a permit
// for the allowed ranges and loopback, and a block for the apps (conditions
// on one field are ORed, so one filter covers every app).
func (w *wfpRuleset) Set(r Rules) error {
	var apps []wfp.Condition
	for _, p := range r.BlockApps {
		id, err := wfp.AppID(p)
		if err != nil {
			continue // removed since it was found: looked for again on the next refresh
		}
		apps = append(apps, wfp.Condition{Field: wfp.FieldALEAppID, Value: wfp.AppIDValue(id)})
	}
	var allow4, allow6 []wfp.Condition
	for _, p := range append(append([]netip.Prefix{}, loopback...), r.Allow...) {
		c := wfp.Condition{Field: wfp.FieldIPRemoteAddress, Value: wfp.Prefix(p)}
		if p.Addr().Is4() {
			allow4 = append(allow4, c)
		} else {
			allow6 = append(allow6, c)
		}
	}
	var ids []uint64
	err := w.s.Transaction(func() error {
		for _, id := range w.ids {
			if err := w.s.DeleteFilter(id); err != nil {
				return err
			}
		}
		if len(apps) == 0 {
			return nil
		}
		for _, l := range []struct {
			layer windows.GUID
			allow []wfp.Condition
		}{{wfp.LayerALEAuthConnectV4, allow4}, {wfp.LayerALEAuthConnectV6, allow6}} {
			if len(l.allow) > 0 {
				id, err := w.s.AddFilter(wfp.Filter{Name: "SentinelGo: allowed destinations", Layer: l.layer,
					Sublayer: netSublayer, Weight: weightAllow, Action: wfp.Permit, Conditions: l.allow})
				if err != nil {
					return err
				}
				ids = append(ids, id)
			}
			id, err := w.s.AddFilter(wfp.Filter{Name: "SentinelGo: blocked apps", Layer: l.layer,
				Sublayer: netSublayer, Weight: weightBlock, Action: wfp.Block, Conditions: apps})
			if err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return nil
	})
	if err != nil {
		return err
	}
	w.ids = ids
	return nil
}

func (w *wfpRuleset) Close() error { return w.s.Close() }

// platformEnv is the service's environment, names in lower case.
func platformEnv() map[string]string {
	env := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok && k != "" {
			env[strings.ToLower(k)] = v
		}
	}
	return env
}

// notProfiles are folders under the profiles folder that aren't users.
var notProfiles = map[string]bool{"public": true, "default": true, "default user": true, "all users": true, "defaultapppool": true}

// platformProfiles lists the user profile folders (C:\Users\<name>).
func platformProfiles() []string {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_UserProfiles, 0)
	if err != nil || dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && !notProfiles[strings.ToLower(e.Name())] {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

func platformExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}
