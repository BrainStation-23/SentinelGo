package desktopproxy

import (
	"fmt"
	"strings"
)

// A proxyStore is one place a desktop keeps its proxy setting.
type proxyStore interface {
	name() string
	// read returns the current values of the keys the store changes.
	read() (map[string]string, error)
	// ours reports whether vals point at pacURL.
	ours(vals map[string]string, pacURL string) bool
	// existing describes a proxy in vals ("" when there is none).
	existing(vals map[string]string) string
	set(pacURL string) error
	// restore puts back values read earlier ("" means unset / default).
	restore(prev map[string]string) error
}

const (
	gnomeName = "gnome"
	kde5Name  = "kde5"
	kde6Name  = "kde6"
)

// GNOME (and the GTK desktops sharing its schema): org.gnome.system.proxy.
const (
	gnomeSchema  = "org.gnome.system.proxy"
	gnomeMode    = "mode"
	gnomeAutoURL = "autoconfig-url"
)

type gnomeStore struct{ run Runner }

func (gnomeStore) name() string { return gnomeName }

func (g gnomeStore) read() (map[string]string, error) {
	vals := map[string]string{}
	for _, k := range []string{gnomeMode, gnomeAutoURL} {
		out, err := g.run("gsettings", "get", gnomeSchema, k)
		if err != nil {
			return nil, err
		}
		vals[k] = gvariantString(string(out))
	}
	return vals, nil
}

func (gnomeStore) ours(vals map[string]string, pacURL string) bool {
	return vals[gnomeMode] == "auto" && vals[gnomeAutoURL] == pacURL
}

func (gnomeStore) existing(vals map[string]string) string {
	if m := vals[gnomeMode]; m != "" && m != "none" {
		return "mode " + m
	}
	return ""
}

func (g gnomeStore) set(pacURL string) error {
	if _, err := g.run("gsettings", "set", gnomeSchema, gnomeAutoURL, gvariantQuote(pacURL)); err != nil {
		return err
	}
	_, err := g.run("gsettings", "set", gnomeSchema, gnomeMode, gvariantQuote("auto"))
	return err
}

// restore resets a key whose previous value was its default, so the user
// keeps following the system default as before.
func (g gnomeStore) restore(prev map[string]string) error {
	defaults := map[string]string{gnomeMode: "none", gnomeAutoURL: ""}
	for _, k := range []string{gnomeMode, gnomeAutoURL} {
		v, ok := prev[k]
		var err error
		if !ok || v == defaults[k] {
			_, err = g.run("gsettings", "reset", gnomeSchema, k)
		} else {
			_, err = g.run("gsettings", "set", gnomeSchema, k, gvariantQuote(v))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// gvariantString reads the text form gsettings prints for a string or enum
// key: 'value' (or "value" when it holds a single quote).
func gvariantString(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		s = s[1 : len(s)-1]
		var b strings.Builder
		for i := 0; i < len(s); i++ {
			if s[i] == '\\' && i+1 < len(s) {
				i++
			}
			b.WriteByte(s[i])
		}
		return b.String()
	}
	return s
}

// gvariantQuote writes s as a GVariant string literal for gsettings set.
func gvariantQuote(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

// KDE Plasma: the "Proxy Settings" group of kioslaverc. ProxyType 0 is no
// proxy, 1 manual, 2 a PAC script, 3 WPAD, 4 environment variables.
const (
	kdeFile      = "kioslaverc"
	kdeGroup     = "Proxy Settings"
	kdeType      = "ProxyType"
	kdeScript    = "Proxy Config Script"
	kdeTypePAC   = "2"
	kdeTypeNone  = "0"
	kdeReparse   = "org.kde.KIO.Scheduler.reparseSlaveConfiguration"
	kdeScheduler = "/KIO/Scheduler"
)

type kdeStore struct {
	run     Runner
	has     func(string) bool
	version string // "5" or "6"
}

func (k kdeStore) name() string { return "kde" + k.version }

func (k kdeStore) read() (map[string]string, error) {
	vals := map[string]string{}
	for _, key := range []string{kdeType, kdeScript} {
		out, err := k.run("kreadconfig"+k.version, "--file", kdeFile, "--group", kdeGroup, "--key", key)
		if err != nil {
			return nil, err
		}
		vals[key] = strings.TrimSpace(string(out))
	}
	return vals, nil
}

func (kdeStore) ours(vals map[string]string, pacURL string) bool {
	return vals[kdeType] == kdeTypePAC && vals[kdeScript] == pacURL
}

func (kdeStore) existing(vals map[string]string) string {
	if t := vals[kdeType]; t != "" && t != kdeTypeNone {
		return "ProxyType " + t
	}
	return ""
}

func (k kdeStore) write(key, value string) error {
	_, err := k.run("kwriteconfig"+k.version, "--file", kdeFile, "--group", kdeGroup, "--key", key, value)
	return err
}

func (k kdeStore) set(pacURL string) error {
	if err := k.write(kdeScript, pacURL); err != nil {
		return err
	}
	if err := k.write(kdeType, kdeTypePAC); err != nil {
		return err
	}
	k.reparse()
	return nil
}

// restore deletes a key that wasn't set before.
func (k kdeStore) restore(prev map[string]string) error {
	for _, key := range []string{kdeType, kdeScript} {
		var err error
		if v := prev[key]; v == "" {
			_, err = k.run("kwriteconfig"+k.version, "--file", kdeFile, "--group", kdeGroup, "--key", key, "--delete")
		} else {
			err = k.write(key, v)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}
	k.reparse()
	return nil
}

// reparse tells running KDE apps to reread the setting (best effort: new
// processes read it anyway).
func (k kdeStore) reparse() {
	if k.has("dbus-send") {
		_, _ = k.run("dbus-send", "--session", "--type=signal", kdeScheduler, kdeReparse, "string:")
	}
}
