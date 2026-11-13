package uploadproxy

import (
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// notifies counts the WinINet change notifications (scratchRegistry's stub).
var notifies atomic.Int64

// scratchRegistry points hklm and hku at a throwaway tree under HKCU, so the
// redirector runs without admin rights and touches nothing real, and
// counts WinINet notifications in notifies instead of sending them.
func scratchRegistry(t *testing.T) (machine, users registry.Key) {
	t.Helper()
	base := fmt.Sprintf(`Software\SentinelGoTest\%d`, time.Now().UnixNano())
	root, _, err := registry.CreateKey(registry.CURRENT_USER, base, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	mk, _, err := registry.CreateKey(root, "HKLM", registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	uk, _, err := registry.CreateKey(root, "HKU", registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	// The machine Internet Settings key exists on every Windows.
	k, _, err := registry.CreateKey(mk, machineInternetSettings, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	_ = k.Close()
	prevM, prevU, prevN := hklm, hku, notifyProxyChange
	hklm, hku = mk, uk
	notifyProxyChange = func() { notifies.Add(1) }
	t.Cleanup(func() {
		hklm, hku, notifyProxyChange = prevM, prevU, prevN
		_ = mk.Close()
		_ = uk.Close()
		_ = root.Close()
		deleteTree(registry.CURRENT_USER, base)
	})
	return mk, uk
}

func deleteTree(root registry.Key, path string) {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS)
	if err == nil {
		names, _ := k.ReadSubKeyNames(-1)
		_ = k.Close()
		for _, n := range names {
			deleteTree(root, path+`\`+n)
		}
	}
	_ = registry.DeleteKey(root, path)
}

func value(t *testing.T, root registry.Key, path, name string) (string, bool) {
	t.Helper()
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer func() { _ = k.Close() }()
	if s, _, err := k.GetStringValue(name); err == nil {
		return s, true
	}
	if n, _, err := k.GetIntegerValue(name); err == nil {
		return fmt.Sprint(n), true
	}
	return "", false
}

func TestWinRedirector(t *testing.T) {
	machine, users := scratchRegistry(t)
	r := NewRedirector(t.TempDir())
	const pac = "http://127.0.0.1:3129/proxy.pac"
	if _, err := r.Apply(pac); err != nil {
		t.Fatal(err)
	}
	if v, ok := value(t, machine, machineInternetSettings, "AutoConfigURL"); !ok || v != pac {
		t.Errorf("AutoConfigURL %q %v", v, ok)
	}
	if v, ok := value(t, machine, policyInternetSettings, "ProxySettingsPerUser"); !ok || v != "0" {
		t.Errorf("ProxySettingsPerUser %q %v", v, ok)
	}
	if repaired, err := r.Apply(pac); err != nil || repaired { // again: nothing changes
		t.Fatal(repaired, err)
	}
	// A crashed agent: a new redirector finds the note and undoes it.
	if err := NewRedirector(r.(*winRedirector).dir).Remove(); err != nil {
		t.Fatal(err)
	}
	if _, ok := value(t, machine, machineInternetSettings, "AutoConfigURL"); ok {
		t.Error("AutoConfigURL left")
	}
	if _, ok := value(t, machine, policyInternetSettings, "ProxySettingsPerUser"); ok {
		t.Error("ProxySettingsPerUser left")
	}

	// A user with their own proxy: stand down, change nothing.
	uk, _, err := registry.CreateKey(users, `S-1-5-21-1-2-3-1001\`+userInternetSettings, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	_ = uk.SetDWordValue("ProxyEnable", 1)
	_ = uk.Close()
	if _, err := r.Apply(pac); !errors.Is(err, ErrExistingProxy) {
		t.Errorf("a user's proxy: %v", err)
	}
	if _, ok := value(t, machine, machineInternetSettings, "AutoConfigURL"); ok {
		t.Error("changed despite an existing proxy")
	}
	_ = registry.DeleteKey(users, `S-1-5-21-1-2-3-1001\`+userInternetSettings)

	// The admin's own machine proxy policy: stand down.
	pk, _, _ := registry.CreateKey(machine, policyInternetSettings, registry.ALL_ACCESS)
	_ = pk.SetDWordValue("ProxySettingsPerUser", 0)
	_ = pk.Close()
	if _, err := r.Apply(pac); !errors.Is(err, ErrExistingProxy) {
		t.Errorf("a policy-managed proxy: %v", err)
	}
	_ = registry.DeleteKey(machine, policyInternetSettings)

	// Someone changes the URL after us: Remove leaves theirs.
	if _, err := r.Apply(pac); err != nil {
		t.Fatal(err)
	}
	mk, _ := registry.OpenKey(machine, machineInternetSettings, registry.SET_VALUE)
	_ = mk.SetStringValue("AutoConfigURL", "http://corp/proxy.pac")
	_ = mk.Close()
	if err := r.Remove(); err != nil {
		t.Fatal(err)
	}
	if v, _ := value(t, machine, machineInternetSettings, "AutoConfigURL"); v != "http://corp/proxy.pac" {
		t.Errorf("someone else's URL removed: %q", v)
	}
}

// modTime is a key's last write time.
func modTime(t *testing.T, root registry.Key, path string) time.Time {
	t.Helper()
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = k.Close() }()
	st, err := k.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return st.ModTime()
}

// Apply checks the registry, not its note (#477): it writes back what was
// removed, leaves another product's proxy alone, and writes nothing when
// nothing changed.
func TestWinRedirector_Repair(t *testing.T) {
	machine, _ := scratchRegistry(t)
	dir := t.TempDir()
	r := NewRedirector(dir)
	const pac = "http://127.0.0.1:3129/proxy.pac"
	if _, err := r.Apply(pac); err != nil {
		t.Fatal(err)
	}
	if notifies.Load() == 0 {
		t.Error("the first Apply didn't tell WinINet")
	}

	// Nothing changed: no registry writes, no note write, no broadcast.
	pkTime, mkTime := modTime(t, machine, policyInternetSettings), modTime(t, machine, machineInternetSettings)
	noteInfo, err := os.Stat(r.(*winRedirector).notePath())
	if err != nil {
		t.Fatal(err)
	}
	before := notifies.Load()
	time.Sleep(20 * time.Millisecond)
	for range 3 {
		if repaired, err := r.Apply(pac); err != nil || repaired {
			t.Fatalf("unchanged: repaired %v, %v", repaired, err)
		}
	}
	if !modTime(t, machine, policyInternetSettings).Equal(pkTime) || !modTime(t, machine, machineInternetSettings).Equal(mkTime) {
		t.Error("an unchanged Apply wrote the registry")
	}
	if fi, _ := os.Stat(r.(*winRedirector).notePath()); fi == nil || !fi.ModTime().Equal(noteInfo.ModTime()) {
		t.Error("an unchanged Apply wrote the note")
	}
	if notifies.Load() != before {
		t.Error("an unchanged Apply told WinINet")
	}

	// AutoConfigURL deleted: written back, and WinINet told.
	mk, _ := registry.OpenKey(machine, machineInternetSettings, registry.SET_VALUE)
	_ = mk.DeleteValue("AutoConfigURL")
	_ = mk.Close()
	if repaired, err := r.Apply(pac); err != nil || !repaired {
		t.Fatalf("AutoConfigURL deleted: repaired %v, %v", repaired, err)
	}
	if v, _ := value(t, machine, machineInternetSettings, "AutoConfigURL"); v != pac {
		t.Errorf("AutoConfigURL %q", v)
	}
	if notifies.Load() == before {
		t.Error("a repair didn't tell WinINet")
	}

	// ProxySettingsPerUser deleted: written back the same way.
	pk, _ := registry.OpenKey(machine, policyInternetSettings, registry.SET_VALUE)
	_ = pk.DeleteValue("ProxySettingsPerUser")
	_ = pk.Close()
	if repaired, err := r.Apply(pac); err != nil || !repaired {
		t.Fatalf("ProxySettingsPerUser deleted: repaired %v, %v", repaired, err)
	}
	if v, ok := value(t, machine, policyInternetSettings, "ProxySettingsPerUser"); !ok || v != "0" {
		t.Errorf("ProxySettingsPerUser %q %v", v, ok)
	}
	// The whole policy key gone: created again.
	_ = registry.DeleteKey(machine, policyInternetSettings)
	if repaired, err := r.Apply(pac); err != nil || !repaired {
		t.Fatalf("policy key deleted: repaired %v, %v", repaired, err)
	}

	// Remove after repairs still restores the values from before the first
	// Apply (neither was there).
	if err := r.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, ok := value(t, machine, machineInternetSettings, "AutoConfigURL"); ok {
		t.Error("AutoConfigURL left after Remove")
	}
	if _, ok := value(t, machine, policyInternetSettings, "ProxySettingsPerUser"); ok {
		t.Error("ProxySettingsPerUser left after Remove")
	}

	// Another product's URL: not overwritten, ErrExistingProxy, and Remove
	// leaves it too.
	if _, err := r.Apply(pac); err != nil {
		t.Fatal(err)
	}
	mk, _ = registry.OpenKey(machine, machineInternetSettings, registry.SET_VALUE)
	_ = mk.SetStringValue("AutoConfigURL", "http://corp/proxy.pac")
	_ = mk.Close()
	for range 2 {
		if repaired, err := r.Apply(pac); !errors.Is(err, ErrExistingProxy) || repaired {
			t.Errorf("another URL: repaired %v, %v", repaired, err)
		}
	}
	if v, _ := value(t, machine, machineInternetSettings, "AutoConfigURL"); v != "http://corp/proxy.pac" {
		t.Errorf("another product's URL overwritten: %q", v)
	}
	// It goes away again: ours comes back.
	mk, _ = registry.OpenKey(machine, machineInternetSettings, registry.SET_VALUE)
	_ = mk.DeleteValue("AutoConfigURL")
	_ = mk.Close()
	if repaired, err := r.Apply(pac); err != nil || !repaired {
		t.Fatalf("after theirs went: repaired %v, %v", repaired, err)
	}

	// Per-user settings switched back on by someone: theirs, for Apply and
	// for Remove.
	pk, _ = registry.OpenKey(machine, policyInternetSettings, registry.SET_VALUE)
	_ = pk.SetDWordValue("ProxySettingsPerUser", 1)
	_ = pk.Close()
	if _, err := r.Apply(pac); !errors.Is(err, ErrExistingProxy) {
		t.Errorf("per-user policy: %v", err)
	}
	if err := r.Remove(); err != nil {
		t.Fatal(err)
	}
	if v, ok := value(t, machine, policyInternetSettings, "ProxySettingsPerUser"); !ok || v != "1" {
		t.Errorf("their ProxySettingsPerUser changed: %q %v", v, ok)
	}
	if _, ok := value(t, machine, machineInternetSettings, "AutoConfigURL"); ok {
		t.Error("our AutoConfigURL left after Remove")
	}
}

// The real Root store, as admin (CI runners are): trust, then untrust.
func TestWinTruster(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated prompt: the local machine Root store needs admin")
	}
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := NewTruster()
	if err := tr.Trust(ca); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Untrust() })
	if !trustSettles(ca, true) {
		t.Error("not trusted after Trust")
	}
	if err := tr.Untrust(); err != nil {
		t.Fatal(err)
	}
	if !trustSettles(ca, false) {
		t.Error("still trusted after Untrust")
	}
}

// trustSettles waits until the system's verdict on ca is want. The chain
// engine caches the Root store and picks up a change through a registry
// notification, so a verify right after Trust or Untrust can still see the
// old store.
func trustSettles(ca *CA, want bool) bool {
	deadline := time.Now().Add(10 * time.Second)
	for {
		if systemTrusts(ca) == want {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}
