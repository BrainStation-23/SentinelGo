package uploadproxy

// Windows: the PAC script is set as the machine-wide proxy auto-config
// (the "make proxy settings per-machine" policy plus AutoConfigURL in the
// machine's Internet Settings), which Edge, Chrome and WinINet apps follow.
// The CA goes in the local machine's Root store through crypt32. Nothing
// needs a driver.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	policyInternetSettings  = `SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings`
	machineInternetSettings = `SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings`
	userInternetSettings    = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	redirectNote            = "upload-redirect.json"
)

// Test seam: the registry roots.
var (
	hklm = registry.LOCAL_MACHINE
	hku  = registry.USERS
)

type winRedirector struct{ dir string }

// NewRedirector returns this OS's Redirector; dir holds its note.
func NewRedirector(dir string) Redirector { return &winRedirector{dir: dir} }

// platformRedirector is the machine-wide setting; helpers aren't needed.
func platformRedirector(o ServiceOptions) Redirector { return NewRedirector(o.ConfigDir) }

// winNote is what Apply changed, to undo it exactly.
type winNote struct {
	PACURL string `json:"pac_url"`
	// The values before Apply: present or not, and what they were.
	HadPerUser    bool   `json:"had_per_user"`
	PerUser       uint32 `json:"per_user"`
	HadAutoConfig bool   `json:"had_auto_config"`
	AutoConfig    string `json:"auto_config"`
}

func (r *winRedirector) notePath() string { return filepath.Join(r.dir, redirectNote) }

func (r *winRedirector) Apply(pacURL string) (bool, error) {
	if note, ok := r.readNote(); ok && note.PACURL == pacURL {
		return r.check(pacURL)
	}
	if err := r.Remove(); err != nil {
		return false, err
	}
	if err := existingProxy(); err != nil {
		return false, err
	}
	note := winNote{PACURL: pacURL}
	pk, _, err := registry.CreateKey(hklm, policyInternetSettings, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return false, fmt.Errorf("proxy policy key: %w", err)
	}
	defer func() { _ = pk.Close() }()
	mk, err := registry.OpenKey(hklm, machineInternetSettings, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return false, fmt.Errorf("machine Internet Settings: %w", err)
	}
	defer func() { _ = mk.Close() }()
	if v, _, err := pk.GetIntegerValue("ProxySettingsPerUser"); err == nil {
		note.HadPerUser, note.PerUser = true, uint32(v) // #nosec G115 -- a DWORD
	}
	if v, _, err := mk.GetStringValue("AutoConfigURL"); err == nil {
		note.HadAutoConfig, note.AutoConfig = true, v
	}
	// The note first: a crash between the two writes is then still undone.
	if err := r.writeNote(note); err != nil {
		return false, err
	}
	if err := pk.SetDWordValue("ProxySettingsPerUser", 0); err != nil {
		_ = r.Remove()
		return false, fmt.Errorf("per-machine proxy settings: %w", err)
	}
	if err := mk.SetStringValue("AutoConfigURL", pacURL); err != nil {
		_ = r.Remove()
		return false, fmt.Errorf("auto-config URL: %w", err)
	}
	notifyProxyChange()
	return false, nil
}

// check is Apply once the note says pacURL is applied: it trusts the
// registry, not the note (#477). Both values still ours: nothing to do and
// nothing written (the watchdog calls this every watchdogEvery). One
// missing (deleted by the Settings app, an update, another tool): it is
// written again, and the note keeps the values from before the first Apply
// so Remove still restores them. One set to something else: another product
// owns the proxy now, so it is left alone, the same rule Remove follows.
// existingProxy isn't asked: it counts our own ProxySettingsPerUser as a
// proxy policy.
func (r *winRedirector) check(pacURL string) (bool, error) {
	perUser, hasPerUser := machineDWord(policyInternetSettings, "ProxySettingsPerUser")
	auto := machineString(machineInternetSettings, "AutoConfigURL")
	switch {
	case hasPerUser && perUser != 0:
		return false, fmt.Errorf("%w: proxy settings are per user again (policy)", ErrExistingProxy)
	case auto != "" && auto != pacURL:
		return false, fmt.Errorf("%w: another auto-config URL is set", ErrExistingProxy)
	case hasPerUser && auto == pacURL:
		return false, nil
	}
	if !hasPerUser {
		pk, _, err := registry.CreateKey(hklm, policyInternetSettings, registry.SET_VALUE)
		if err != nil {
			return false, fmt.Errorf("proxy policy key: %w", err)
		}
		err = pk.SetDWordValue("ProxySettingsPerUser", 0)
		_ = pk.Close()
		if err != nil {
			return false, fmt.Errorf("per-machine proxy settings: %w", err)
		}
	}
	if auto == "" {
		mk, err := registry.OpenKey(hklm, machineInternetSettings, registry.SET_VALUE)
		if err != nil {
			return false, fmt.Errorf("machine Internet Settings: %w", err)
		}
		err = mk.SetStringValue("AutoConfigURL", pacURL)
		_ = mk.Close()
		if err != nil {
			return false, fmt.Errorf("auto-config URL: %w", err)
		}
	}
	notifyProxyChange()
	return true, nil
}

// machineDWord reads a DWORD under hklm; present reports that the value
// exists. A value of another type counts as present and not ours.
func machineDWord(path, name string) (v uint64, present bool) {
	k, err := registry.OpenKey(hklm, path, registry.QUERY_VALUE)
	if err != nil {
		return 0, false
	}
	defer func() { _ = k.Close() }()
	v, _, err = k.GetIntegerValue(name)
	switch {
	case err == nil:
		return v, true
	case errors.Is(err, registry.ErrNotExist):
		return 0, false
	default:
		return ^uint64(0), true
	}
}

// machineString reads a string under hklm; "" when missing or unreadable.
func machineString(path, name string) string {
	k, err := registry.OpenKey(hklm, path, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer func() { _ = k.Close() }()
	v, _, _ := k.GetStringValue(name)
	return v
}

func (r *winRedirector) Remove() error {
	note, ok := r.readNote()
	if !ok {
		return nil
	}
	if pk, err := registry.OpenKey(hklm, policyInternetSettings, registry.QUERY_VALUE|registry.SET_VALUE); err == nil {
		cur, _, perr := pk.GetIntegerValue("ProxySettingsPerUser")
		switch {
		case (perr == nil && cur != 0) || (perr != nil && !errors.Is(perr, registry.ErrNotExist)):
			// Someone changed it since: theirs now, leave it (as Apply does).
		case note.HadPerUser:
			_ = pk.SetDWordValue("ProxySettingsPerUser", note.PerUser)
		default:
			_ = pk.DeleteValue("ProxySettingsPerUser")
		}
		_ = pk.Close()
	}
	if mk, err := registry.OpenKey(hklm, machineInternetSettings, registry.QUERY_VALUE|registry.SET_VALUE); err == nil {
		cur, _, _ := mk.GetStringValue("AutoConfigURL")
		switch {
		case cur != note.PACURL:
			// Someone changed it since: theirs now, leave it.
		case note.HadAutoConfig:
			_ = mk.SetStringValue("AutoConfigURL", note.AutoConfig)
		default:
			_ = mk.DeleteValue("AutoConfigURL")
		}
		_ = mk.Close()
	}
	if err := os.Remove(r.notePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove the redirect note: %w", err)
	}
	notifyProxyChange()
	return nil
}

// WinINet options that make running apps reread the proxy settings.
const (
	internetOptionRefresh         = 37 // INTERNET_OPTION_REFRESH
	internetOptionSettingsChanged = 39 // INTERNET_OPTION_SETTINGS_CHANGED
)

var procInternetSetOption = windows.NewLazySystemDLL("wininet.dll").NewProc("InternetSetOptionW")

// notifyProxyChange tells WinINet the proxy settings changed, so running
// browsers and WinINet apps pick up (or drop) the PAC without a restart.
// Best effort, and only after a write. A seam for tests.
var notifyProxyChange = func() {
	if procInternetSetOption.Find() != nil {
		return // no WinINet (Server Core): nothing caches the settings
	}
	for _, opt := range []uintptr{internetOptionSettingsChanged, internetOptionRefresh} {
		_, _, _ = procInternetSetOption.Call(0, opt, 0, 0)
	}
}

func (r *winRedirector) readNote() (winNote, bool) {
	b, err := os.ReadFile(r.notePath())
	if err != nil {
		return winNote{}, false
	}
	var n winNote
	if json.Unmarshal(b, &n) != nil || n.PACURL == "" {
		return winNote{}, false
	}
	return n, true
}

func (r *winRedirector) writeNote(n winNote) error {
	b, err := json.Marshal(n)
	if err != nil {
		return err
	}
	return writeFileAtomic(r.notePath(), b, 0o600, true)
}

// existingProxy reports a proxy set by someone else: the per-machine policy,
// a machine auto-config or proxy server, or a logged-on user's own proxy or
// auto-config.
func existingProxy() error {
	if pk, err := registry.OpenKey(hklm, policyInternetSettings, registry.QUERY_VALUE); err == nil {
		_, _, perr := pk.GetIntegerValue("ProxySettingsPerUser")
		_ = pk.Close()
		if perr == nil {
			return fmt.Errorf("%w: proxy settings are managed by policy", ErrExistingProxy)
		}
	}
	if configured(hklm, machineInternetSettings) {
		return fmt.Errorf("%w: a machine proxy is set", ErrExistingProxy)
	}
	users, err := registry.OpenKey(hku, "", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer func() { _ = users.Close() }()
	sids, _ := users.ReadSubKeyNames(-1)
	for _, sid := range sids {
		if !strings.HasPrefix(sid, "S-1-5-21-") || strings.HasSuffix(sid, "_Classes") {
			continue
		}
		if configured(hku, sid+`\`+userInternetSettings) {
			return fmt.Errorf("%w: a user's proxy is set", ErrExistingProxy)
		}
	}
	return nil
}

// configured reports a proxy server turned on, or an auto-config URL, in an
// Internet Settings key.
func configured(root registry.Key, path string) bool {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer func() { _ = k.Close() }()
	if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil && v != 0 {
		return true
	}
	if v, _, err := k.GetStringValue("AutoConfigURL"); err == nil && v != "" {
		return true
	}
	return false
}

// winTruster uses the local machine's Root store.
type winTruster struct{}

// NewTruster returns this OS's Truster.
func NewTruster() Truster { return winTruster{} }

const encoding = windows.X509_ASN_ENCODING | windows.PKCS_7_ASN_ENCODING

func openRoot() (windows.Handle, error) {
	name, _ := windows.UTF16PtrFromString("ROOT")
	return windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0, windows.CERT_SYSTEM_STORE_LOCAL_MACHINE, uintptr(unsafe.Pointer(name)))
}

func (winTruster) Trust(ca *CA) error {
	der := ca.Certificate().Raw
	store, err := openRoot()
	if err != nil {
		return fmt.Errorf("open the Root store: %w", err)
	}
	defer func() { _ = windows.CertCloseStore(store, 0) }()
	// Take out older inspection CAs (a renewed CA) first.
	removeOurs(store, der)
	ctx, err := windows.CertCreateCertificateContext(encoding, &der[0], uint32(len(der)))
	if err != nil {
		return fmt.Errorf("read the CA: %w", err)
	}
	defer func() { _ = windows.CertFreeCertificateContext(ctx) }()
	if err := windows.CertAddCertificateContextToStore(store, ctx, windows.CERT_STORE_ADD_REPLACE_EXISTING, nil); err != nil {
		return fmt.Errorf("add the CA to the Root store: %w", err)
	}
	return nil
}

func (winTruster) Untrust() error {
	store, err := openRoot()
	if err != nil {
		return fmt.Errorf("open the Root store: %w", err)
	}
	defer func() { _ = windows.CertCloseStore(store, 0) }()
	removeOurs(store, nil)
	return nil
}

// removeOurs deletes every inspection CA in store except keep.
func removeOurs(store windows.Handle, keep []byte) {
	var prev *windows.CertContext
	for {
		ctx, err := windows.CertEnumCertificatesInStore(store, prev)
		if err != nil || ctx == nil {
			return
		}
		der := unsafe.Slice(ctx.EncodedCert, ctx.Length)
		if isOurCA(der) && string(der) != string(keep) {
			// Delete frees ctx; continue from a duplicate so the walk goes on.
			dup := windows.CertDuplicateCertificateContext(ctx)
			_ = windows.CertDeleteCertificateFromStore(dup)
		}
		prev = ctx
	}
}
