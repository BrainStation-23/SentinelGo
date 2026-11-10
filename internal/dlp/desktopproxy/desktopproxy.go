// Package desktopproxy points a Linux user's desktop proxy setting at the
// upload inspection's PAC script (#426), and puts it back exactly as it was.
//
// The setting is per user (GNOME: the org.gnome.system.proxy GSettings
// schema; KDE: kioslaverc), so the session helper does this as the user,
// when the service asks. Chrome and Chromium follow it, and so does Firefox
// with "Use system proxy settings" (its default).
//
// It stands down (ErrExistingProxy, nothing changed) when the user already
// has a proxy that isn't ours: two interceptors break things. Before
// changing anything it writes a note of the previous values to the user's
// state directory, so a helper that was killed restores them when it next
// starts (fail open). Values someone changed since are theirs: they are
// never overwritten on restore.
//
// It only runs the desktop's own command-line tools (gsettings,
// kreadconfig/kwriteconfig), never a library: no cgo, no new dependency.
package desktopproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Errors Set reports; Reason turns them into capability reasons.
var (
	// ErrExistingProxy: the user has a proxy that isn't ours.
	ErrExistingProxy = errors.New("existing_proxy")
	// ErrUnsupportedDesktop: neither GSettings nor KDE's tools are there.
	ErrUnsupportedDesktop = errors.New("unsupported_desktop")
)

// Reason is the capability reason for a Set error ("" for nil).
func Reason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrExistingProxy):
		return ErrExistingProxy.Error()
	case errors.Is(err, ErrUnsupportedDesktop):
		return ErrUnsupportedDesktop.Error()
	}
	return "error"
}

// Runner runs a desktop tool and returns its standard output.
type Runner func(name string, args ...string) ([]byte, error)

// Options are a Manager's OS seams (tests replace them).
type Options struct {
	Run Runner
	// Has reports whether a tool is installed.
	Has func(name string) bool
	// Desktop is $XDG_CURRENT_DESKTOP, KDESession $KDE_SESSION_VERSION.
	Desktop, KDESession string
	// NotePath is where the previous values are kept while ours are set.
	NotePath string
}

// Manager sets and clears the desktop proxy for one user. It is safe for
// concurrent use.
type Manager struct {
	o  Options
	mu sync.Mutex
}

// NewManager returns a Manager with the given seams.
func NewManager(o Options) *Manager { return &Manager{o: o} }

// note is what the Manager changed: the PAC URL, and per store the values
// it replaced ("" for a key that was unset or at its default).
type note struct {
	PACURL   string                       `json:"pac_url"`
	Previous map[string]map[string]string `json:"previous"`
}

// Set points the desktop proxy at pacURL; "" clears it (Clear). It does
// nothing when the setting already is ours.
func (m *Manager) Set(pacURL string) error {
	if pacURL == "" {
		return m.Clear()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	stores := m.detect()
	if len(stores) == 0 {
		return fmt.Errorf("%w: no GNOME or KDE proxy setting for this user", ErrUnsupportedDesktop)
	}
	n, have := m.readNote()
	cur, err := m.current(stores, pacURL, n, have)
	if err != nil {
		return err
	}
	next := nextNote(stores, cur, pacURL, n)
	// The note goes first: a crash between it and the change only costs a
	// restore that finds nothing of ours.
	if err := m.writeNote(next); err != nil {
		return fmt.Errorf("write the proxy note: %w", err)
	}
	for i, s := range stores {
		if s.ours(cur[s.name()], pacURL) {
			continue
		}
		if err := s.set(pacURL); err != nil {
			// Half set isn't "ours" yet, so undo what was touched outright.
			m.rollback(stores[:i+1], next)
			return fmt.Errorf("set the %s proxy: %w", s.name(), err)
		}
	}
	return nil
}

// current reads every store's values. A store with someone else's proxy
// (possibly set over ours) is ErrExistingProxy: Set stands down, and gives
// back what is still ours.
func (m *Manager) current(stores []proxyStore, pacURL string, n note, have bool) (map[string]map[string]string, error) {
	cur := make(map[string]map[string]string, len(stores))
	for _, s := range stores {
		vals, err := s.read()
		if err != nil {
			return nil, fmt.Errorf("read the %s proxy setting: %w", s.name(), err)
		}
		cur[s.name()] = vals
		what := s.existing(vals)
		if what == "" || s.ours(vals, pacURL) || (have && s.ours(vals, n.PACURL)) {
			continue
		}
		err = fmt.Errorf("%w: %s %s", ErrExistingProxy, s.name(), what)
		if have {
			if cerr := m.clearLocked(); cerr != nil {
				err = fmt.Errorf("%w (and restoring ours failed: %v)", err, cerr)
			}
		}
		return nil, err
	}
	return cur, nil
}

// nextNote is the note for setting pacURL over cur: a store already in the
// old note keeps its original previous values.
func nextNote(stores []proxyStore, cur map[string]map[string]string, pacURL string, old note) note {
	next := note{PACURL: pacURL, Previous: map[string]map[string]string{}}
	for _, s := range stores {
		name := s.name()
		switch prev, ok := old.Previous[name]; {
		case ok:
			next.Previous[name] = prev
		case s.ours(cur[name], pacURL):
			// Ours without a note (it was lost): the previous values are
			// unknown, so restore means back to the defaults.
			next.Previous[name] = map[string]string{}
		default:
			next.Previous[name] = cur[name]
		}
	}
	return next
}

// rollback restores stores to their values in n after a failed Set, and
// drops the note when that worked.
func (m *Manager) rollback(stores []proxyStore, n note) {
	for _, s := range stores {
		if s.restore(n.Previous[s.name()]) != nil {
			return // the note stays: Clear tries again
		}
	}
	_ = os.Remove(m.o.NotePath)
}

// Clear restores what Set changed (also after a crash, from the note).
// Values changed by someone else since are left alone. It does nothing
// when nothing was set.
func (m *Manager) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.clearLocked()
}

func (m *Manager) clearLocked() error {
	n, ok := m.readNote()
	if !ok {
		return nil
	}
	var errs []error
	names := make([]string, 0, len(n.Previous))
	for name := range n.Previous {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		s := m.store(name)
		if s == nil {
			continue // its tool is gone: nothing can be read or restored
		}
		vals, err := s.read()
		if err != nil {
			errs = append(errs, fmt.Errorf("read the %s proxy setting: %w", name, err))
			continue
		}
		if !s.ours(vals, n.PACURL) {
			continue // changed since: theirs now
		}
		if err := s.restore(n.Previous[name]); err != nil {
			errs = append(errs, fmt.Errorf("restore the %s proxy setting: %w", name, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...) // the note stays for the next try
	}
	if err := os.Remove(m.o.NotePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove the proxy note: %w", err)
	}
	return nil
}

// detect lists the proxy stores this user's desktop reads. On KDE that is
// kioslaverc, and GSettings as well when it is there (GTK apps on Plasma
// read it).
func (m *Manager) detect() []proxyStore {
	var out []proxyStore
	if m.isKDE() {
		if s := m.kde(); s != nil {
			out = append(out, s)
		}
	}
	if g := m.store(gnomeName); g != nil {
		if _, err := g.read(); err == nil { // the schema is installed
			out = append(out, g)
		}
	}
	return out
}

func (m *Manager) isKDE() bool {
	for _, d := range strings.Split(m.o.Desktop, ":") {
		if strings.EqualFold(strings.TrimSpace(d), "KDE") {
			return true
		}
	}
	return false
}

// kde picks Plasma 6's tools in a Plasma 6 session, else Plasma 5's, else
// whichever is installed.
func (m *Manager) kde() proxyStore {
	order := []string{kde5Name, kde6Name}
	if m.o.KDESession == "6" {
		order = []string{kde6Name, kde5Name}
	}
	for _, name := range order {
		if s := m.store(name); s != nil {
			return s
		}
	}
	return nil
}

// store returns the named store when its tools are installed.
func (m *Manager) store(name string) proxyStore {
	switch name {
	case gnomeName:
		if m.o.Has("gsettings") {
			return gnomeStore{run: m.o.Run}
		}
	case kde5Name, kde6Name:
		v := strings.TrimPrefix(name, "kde")
		if m.o.Has("kreadconfig"+v) && m.o.Has("kwriteconfig"+v) {
			return kdeStore{run: m.o.Run, has: m.o.Has, version: v}
		}
	}
	return nil
}

func (m *Manager) readNote() (note, bool) {
	b, err := os.ReadFile(m.o.NotePath)
	if err != nil {
		return note{}, false
	}
	var n note
	if json.Unmarshal(b, &n) != nil || n.PACURL == "" || n.Previous == nil {
		return note{}, false
	}
	return n, true
}

func (m *Manager) writeNote(n note) error {
	b, err := json.Marshal(n)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.o.NotePath), 0o700); err != nil {
		return err
	}
	tmp := m.o.NotePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.o.NotePath)
}
