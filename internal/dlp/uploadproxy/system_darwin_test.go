package uploadproxy

import (
	"errors"
	"strings"
	"testing"
)

// fakeNetworksetup is networksetup over a few services. Like the real one,
// turning a service's auto proxy off keeps its URL.
type fakeNetworksetup struct {
	auto  map[string]string // service → auto proxy URL
	off   map[string]bool   // service → auto proxy turned off
	extra []string          // services added after the standard ones
	web   bool
	calls []string
}

func newFakeNetworksetup() *fakeNetworksetup {
	return &fakeNetworksetup{auto: map[string]string{}, off: map[string]bool{}}
}

// on is the service's auto proxy URL when it is turned on, else "".
func (f *fakeNetworksetup) on(s string) string {
	if f.off[s] {
		return ""
	}
	return f.auto[s]
}

func (f *fakeNetworksetup) sets() int {
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, "-set") {
			n++
		}
	}
	return n
}

func (f *fakeNetworksetup) run(args ...string) ([]byte, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	switch args[0] {
	case "-listallnetworkservices":
		list := "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\nUSB 10/100 LAN\n*Thunderbolt Bridge\n"
		for _, s := range f.extra {
			list += s + "\n"
		}
		return []byte(list), nil
	case "-getwebproxy", "-getsecurewebproxy":
		if f.web {
			return []byte("Enabled: Yes\nServer: corp\nPort: 8080\n"), nil
		}
		return []byte("Enabled: No\nServer:\nPort: 0\n"), nil
	case "-getautoproxyurl":
		u := f.auto[args[1]]
		if u == "" {
			u = "(null)"
		}
		state := "Yes"
		if f.on(args[1]) == "" {
			state = "No"
		}
		return []byte("URL: " + u + "\nEnabled: " + state + "\n"), nil
	case "-setautoproxyurl":
		f.auto[args[1]], f.off[args[1]] = args[2], false
	case "-setautoproxystate":
		f.off[args[1]] = args[2] == "off"
	default:
		return nil, errors.New("unknown")
	}
	return nil, nil
}

func useFakeNetworksetup(t *testing.T) *fakeNetworksetup {
	t.Helper()
	f := newFakeNetworksetup()
	prev := runNetworksetup
	runNetworksetup = f.run
	t.Cleanup(func() { runNetworksetup = prev })
	return f
}

func TestMacRedirector(t *testing.T) {
	f := useFakeNetworksetup(t)
	dir := t.TempDir()
	r := NewRedirector(dir)
	const pac = "http://127.0.0.1:3129/proxy.pac"
	if _, err := r.Apply(pac); err != nil {
		t.Fatal(err)
	}
	if f.on("Wi-Fi") != pac || f.on("USB 10/100 LAN") != pac || f.on("*Thunderbolt Bridge") != "" {
		t.Errorf("auto proxies %v off %v", f.auto, f.off)
	}
	// A crashed agent's redirect is undone by the next one.
	if err := NewRedirector(dir).Remove(); err != nil {
		t.Fatal(err)
	}
	if f.on("Wi-Fi") != "" || f.on("USB 10/100 LAN") != "" {
		t.Errorf("not removed: %v off %v", f.auto, f.off)
	}
	// An existing web proxy: stand down.
	f.web = true
	if _, err := r.Apply(pac); !errors.Is(err, ErrExistingProxy) {
		t.Errorf("existing proxy: %v", err)
	}
	if f.on("Wi-Fi") != "" {
		t.Error("changed despite an existing proxy")
	}
}

// Apply checks the network services, not its note (#477).
func TestMacRedirector_Repair(t *testing.T) {
	f := useFakeNetworksetup(t)
	dir := t.TempDir()
	r := NewRedirector(dir)
	const pac = "http://127.0.0.1:3129/proxy.pac"
	if _, err := r.Apply(pac); err != nil {
		t.Fatal(err)
	}
	// Nothing changed: reads only.
	sets := f.sets()
	if repaired, err := r.Apply(pac); err != nil || repaired {
		t.Fatalf("unchanged: repaired %v, %v", repaired, err)
	}
	if f.sets() != sets {
		t.Errorf("an unchanged Apply changed settings: %v", f.calls)
	}

	// Turned off in System Settings: on again.
	f.off["Wi-Fi"] = true
	if repaired, err := r.Apply(pac); err != nil || !repaired {
		t.Fatalf("turned off: repaired %v, %v", repaired, err)
	}
	if f.on("Wi-Fi") != pac || f.on("USB 10/100 LAN") != pac {
		t.Errorf("after the repair: %v off %v", f.auto, f.off)
	}

	// A service added since gets it, and Remove turns it off too.
	f.extra = []string{"iPhone USB"}
	if repaired, err := r.Apply(pac); err != nil || !repaired {
		t.Fatalf("new service: repaired %v, %v", repaired, err)
	}
	if f.on("iPhone USB") != pac {
		t.Errorf("new service: %v", f.auto)
	}

	// Another product's URL on one service: left alone, ErrExistingProxy;
	// another service that lost ours still gets it back.
	f.auto["Wi-Fi"] = "http://corp/proxy.pac"
	f.off["USB 10/100 LAN"] = true
	repaired, err := r.Apply(pac)
	if !errors.Is(err, ErrExistingProxy) || !repaired {
		t.Errorf("another URL: repaired %v, %v", repaired, err)
	}
	if f.on("Wi-Fi") != "http://corp/proxy.pac" || f.on("USB 10/100 LAN") != pac {
		t.Errorf("after another URL: %v off %v", f.auto, f.off)
	}

	if err := NewRedirector(dir).Remove(); err != nil {
		t.Fatal(err)
	}
	if f.on("USB 10/100 LAN") != "" || f.on("iPhone USB") != "" {
		t.Errorf("not removed: %v off %v", f.auto, f.off)
	}
	if f.on("Wi-Fi") != "http://corp/proxy.pac" {
		t.Errorf("another product's URL removed: %v", f.auto)
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
