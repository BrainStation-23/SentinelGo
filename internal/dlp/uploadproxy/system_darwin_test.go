package uploadproxy

import (
	"errors"
	"strings"
	"testing"
)

type fakeNetworksetup struct {
	auto  map[string]string // service → auto proxy URL ("" when off)
	web   bool
	calls []string
}

func (f *fakeNetworksetup) run(args ...string) ([]byte, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	switch args[0] {
	case "-listallnetworkservices":
		return []byte("An asterisk (*) denotes that a network service is disabled.\nWi-Fi\nUSB 10/100 LAN\n*Thunderbolt Bridge\n"), nil
	case "-getwebproxy", "-getsecurewebproxy":
		if f.web {
			return []byte("Enabled: Yes\nServer: corp\nPort: 8080\n"), nil
		}
		return []byte("Enabled: No\nServer:\nPort: 0\n"), nil
	case "-getautoproxyurl":
		if u := f.auto[args[1]]; u != "" {
			return []byte("URL: " + u + "\nEnabled: Yes\n"), nil
		}
		return []byte("URL: (null)\nEnabled: No\n"), nil
	case "-setautoproxyurl":
		f.auto[args[1]] = args[2]
	case "-setautoproxystate":
		f.auto[args[1]] = ""
	default:
		return nil, errors.New("unknown")
	}
	return nil, nil
}

func TestMacRedirector(t *testing.T) {
	f := &fakeNetworksetup{auto: map[string]string{}}
	prev := runNetworksetup
	runNetworksetup = f.run
	t.Cleanup(func() { runNetworksetup = prev })
	dir := t.TempDir()
	r := NewRedirector(dir)
	const pac = "http://127.0.0.1:3129/proxy.pac"
	if err := r.Apply(pac); err != nil {
		t.Fatal(err)
	}
	if f.auto["Wi-Fi"] != pac || f.auto["USB 10/100 LAN"] != pac || f.auto["*Thunderbolt Bridge"] != "" {
		t.Errorf("auto proxies %v", f.auto)
	}
	// A crashed agent's redirect is undone by the next one.
	if err := NewRedirector(dir).Remove(); err != nil {
		t.Fatal(err)
	}
	if f.auto["Wi-Fi"] != "" || f.auto["USB 10/100 LAN"] != "" {
		t.Errorf("not removed: %v", f.auto)
	}
	// An existing web proxy: stand down.
	f.web = true
	if err := r.Apply(pac); !errors.Is(err, ErrExistingProxy) {
		t.Errorf("existing proxy: %v", err)
	}
	if f.auto["Wi-Fi"] != "" {
		t.Error("changed despite an existing proxy")
	}
}

func TestMacTruster(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := NewTruster().Trust(ca); !errors.Is(err, ErrNeedsMDM) {
		t.Errorf("an untrusted CA: %v", err)
	}
	if err := NewTruster().Untrust(); err != nil {
		t.Error(err)
	}
}
