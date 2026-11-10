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

func (r *winRedirector) Apply(pacURL string) error {
	if note, ok := r.readNote(); ok && note.PACURL == pacURL {
		return nil // applied already
	}
	if err := r.Remove(); err != nil {
		return err
	}
	if err := existingProxy(); err != nil {
		return err
	}
	note := winNote{PACURL: pacURL}
	pk, _, err := registry.CreateKey(hklm, policyInternetSettings, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("proxy policy key: %w", err)
	}
	defer func() { _ = pk.Close() }()
	mk, err := registry.OpenKey(hklm, machineInternetSettings, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("machine Internet Settings: %w", err)
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
		return err
	}
	if err := pk.SetDWordValue("ProxySettingsPerUser", 0); err != nil {
		_ = r.Remove()
		return fmt.Errorf("per-machine proxy settings: %w", err)
	}
	if err := mk.SetStringValue("AutoConfigURL", pacURL); err != nil {
		_ = r.Remove()
		return fmt.Errorf("auto-config URL: %w", err)
	}
	return nil
}

func (r *winRedirector) Remove() error {
	note, ok := r.readNote()
	if !ok {
		return nil
	}
	if pk, err := registry.OpenKey(hklm, policyInternetSettings, registry.SET_VALUE); err == nil {
		if note.HadPerUser {
			_ = pk.SetDWordValue("ProxySettingsPerUser", note.PerUser)
		} else {
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
	return nil
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
