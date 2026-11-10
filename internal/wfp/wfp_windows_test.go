//go:build windows && (amd64 || arm64)

package wfp

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Offsets from the Windows SDK headers (sizeof/offsetof of FWPM_FILTER0 and
// friends on x64; arm64 has the same layout).
func TestLayouts(t *testing.T) {
	check := func(name string, got, want uintptr) {
		t.Helper()
		if got != want {
			t.Errorf("%s = %d, want %d", name, got, want)
		}
	}
	var s session0
	check("FWPM_SESSION0.flags", unsafe.Offsetof(s.flags), 32)
	check("FWPM_SESSION0.processId", unsafe.Offsetof(s.processID), 40)
	check("FWPM_SESSION0.sid", unsafe.Offsetof(s.sid), 48)
	check("FWPM_SESSION0.kernelMode", unsafe.Offsetof(s.kernelMode), 64)
	var sl sublayer0
	check("FWPM_SUBLAYER0.flags", unsafe.Offsetof(sl.flags), 32)
	check("FWPM_SUBLAYER0.providerKey", unsafe.Offsetof(sl.providerKey), 40)
	check("FWPM_SUBLAYER0.providerData", unsafe.Offsetof(sl.providerData), 48)
	check("FWPM_SUBLAYER0.weight", unsafe.Offsetof(sl.weight), 64)
	var c filterCondition0
	check("FWPM_FILTER_CONDITION0.matchType", unsafe.Offsetof(c.matchType), 16)
	check("FWPM_FILTER_CONDITION0.conditionValue", unsafe.Offsetof(c.conditionValue), 24)
	var f filter0
	check("FWPM_FILTER0.flags", unsafe.Offsetof(f.flags), 32)
	check("FWPM_FILTER0.providerKey", unsafe.Offsetof(f.providerKey), 40)
	check("FWPM_FILTER0.layerKey", unsafe.Offsetof(f.layerKey), 64)
	check("FWPM_FILTER0.subLayerKey", unsafe.Offsetof(f.subLayerKey), 80)
	check("FWPM_FILTER0.weight", unsafe.Offsetof(f.weight), 96)
	check("FWPM_FILTER0.numFilterConditions", unsafe.Offsetof(f.numFilterConditions), 112)
	check("FWPM_FILTER0.filterCondition", unsafe.Offsetof(f.filterCondition), 120)
	check("FWPM_FILTER0.action", unsafe.Offsetof(f.action), 128)
	check("FWPM_FILTER0.rawContext", unsafe.Offsetof(f.rawContext), 152)
	check("FWPM_FILTER0.reserved", unsafe.Offsetof(f.reserved), 168)
	check("FWPM_FILTER0.filterId", unsafe.Offsetof(f.filterID), 176)
	check("FWPM_FILTER0.effectiveWeight", unsafe.Offsetof(f.effectiveWeight), 184)
	check("FWPM_ACTION0", unsafe.Sizeof(action0{}), 20)
	check("FWP_BYTE_BLOB", unsafe.Sizeof(byteBlob{}), 16)
	check("FWP_V4_ADDR_AND_MASK", unsafe.Sizeof(v4AddrAndMask{}), 8)
}

func TestPrefixValues(t *testing.T) {
	v := Prefix(netip.MustParsePrefix("10.1.2.3/32"))
	if v.typ != typeV4AddrMask || v.v4.addr != 0x0a010203 || v.v4.mask != 0xffffffff {
		t.Errorf("v4 %+v", v.v4)
	}
	v = Prefix(netip.MustParsePrefix("10.1.2.3/8"))
	if v.v4.addr != 0x0a000000 || v.v4.mask != 0xff000000 {
		t.Errorf("v4/8 %+v", v.v4)
	}
	v = Prefix(netip.MustParsePrefix("0.0.0.0/0"))
	if v.v4.mask != 0 {
		t.Errorf("v4/0 %+v", v.v4)
	}
	v = Prefix(netip.MustParsePrefix("2001:db8::1/128"))
	if v.typ != typeV6AddrMask || v.v6.prefixLength != 128 || v.v6.addr[0] != 0x20 || v.v6.addr[15] != 1 {
		t.Errorf("v6 %+v", v.v6)
	}
}

func TestMarshalRejects(t *testing.T) {
	if _, _, err := (Filter{Weight: 16, Action: Block}).marshal(); err == nil {
		t.Error("weight 16 accepted")
	}
	if _, _, err := (Filter{Action: 7}).marshal(); err == nil {
		t.Error("unknown action accepted")
	}
	if _, _, err := (Filter{Action: Block, Conditions: []Condition{{Field: FieldALEAppID, Value: AppIDValue(nil)}}}).marshal(); err == nil {
		t.Error("empty app id accepted")
	}
	f, keep, err := (Filter{Name: "x", Action: Permit, Weight: 3, Conditions: []Condition{
		{Field: FieldIPRemotePort, Value: Uint16(443)},
		{Field: FieldIPProtocol, Value: Uint8(ProtocolTCP)},
	}}).marshal()
	if err != nil || f.numFilterConditions != 2 || f.weight.val != 3 || len(keep) == 0 {
		t.Fatalf("%v %+v", err, f)
	}
	conds := unsafe.Slice(f.filterCondition, 2)
	if conds[0].conditionValue.val != 443 || conds[1].conditionValue.typ != typeUint8 {
		t.Errorf("conditions %+v", conds)
	}
}

// AppID and opening a session work without elevation (adding filters
// doesn't).
func TestAppIDAndOpen(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	id, err := AppID(exe)
	if err != nil || len(id) < 8 {
		t.Fatalf("AppID: %v (%d bytes)", err, len(id))
	}
	if _, err := AppID(`C:\does\not\exist.exe`); err == nil {
		t.Error("AppID of a missing file")
	}
	s, err := Open("SentinelGo wfp test")
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Skipf("open: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil { // twice is fine
		t.Fatal(err)
	}
}

// A program started through an 8.3 path (GitHub's runners have TEMP under
// C:\Users\RUNNER~1) has the same app id as through its long path.
func TestAppIDShortPath(t *testing.T) {
	dir := t.TempDir()
	long := dir + `\a long directory name\program.exe`
	if err := os.MkdirAll(long[:len(long)-len(`\program.exe`)], 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(long, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	lp, _ := windows.UTF16PtrFromString(long)
	buf := make([]uint16, windows.MAX_PATH)
	n, err := windows.GetShortPathName(lp, &buf[0], uint32(len(buf)))
	short := windows.UTF16ToString(buf[:n])
	if err != nil || short == long {
		t.Skip("no 8.3 names on this volume")
	}
	if got := longPath(short); !strings.EqualFold(got, long) {
		t.Errorf("longPath(%q) = %q", short, got)
	}
	a, err := AppID(long)
	if err != nil {
		t.Fatal(err)
	}
	b, err := AppID(short)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Error("short path gives another app id")
	}
}

var testSublayer = windows.GUID{Data1: 0x5e4f1c2a, Data2: 0x7b11, Data3: 0x4d6e, Data4: [8]byte{0x9a, 0x01, 0x42, 0x7a, 0x11, 0x0c, 0xd3, 0x27}}

func isAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// listen serves TCP on loopback and returns its port.
func listen(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port) // #nosec G115 -- a port
}

func dials(port uint16) bool {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func blockPort(port uint16) Filter {
	return Filter{Name: "SentinelGo test block", Layer: LayerALEAuthConnectV4, Sublayer: testSublayer, Weight: 1, Action: Block,
		Conditions: []Condition{
			{Field: FieldIPRemoteAddress, Value: Prefix(netip.MustParsePrefix("127.0.0.1/32"))},
			{Field: FieldIPRemotePort, Value: Uint16(port)},
			{Field: FieldIPProtocol, Value: Uint8(ProtocolTCP)},
		}}
}

func openTest(t *testing.T) *Session {
	t.Helper()
	s, err := Open("SentinelGo wfp test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.AddSublayer(testSublayer, "SentinelGo wfp test", 0x100); err != nil {
		t.Fatal(err)
	}
	return s
}

// A dynamic session's block, the app-id exemption, delete, and Close
// removing everything. Needs an elevated process (the CI Windows runner).
func TestSessionRoundTrip(t *testing.T) {
	if !isAdmin() {
		t.Skip("needs an elevated process")
	}
	port := listen(t)
	if !dials(port) {
		t.Fatal("can't dial before any filter")
	}
	s := openTest(t)
	var blockID uint64
	if err := s.Transaction(func() error {
		var err error
		blockID, err = s.AddFilter(blockPort(port))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if dials(port) {
		t.Fatal("dialed through the block")
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	id, err := AppID(exe)
	if err != nil {
		t.Fatal(err)
	}
	permitID, err := s.AddFilter(Filter{Name: "SentinelGo test permit self", Layer: LayerALEAuthConnectV4, Sublayer: testSublayer,
		Weight: 15, Action: Permit, Conditions: []Condition{{Field: FieldALEAppID, Value: AppIDValue(id)}}})
	if err != nil {
		t.Fatal(err)
	}
	if !dials(port) {
		t.Fatal("own app id not exempt")
	}
	if err := s.DeleteFilter(permitID); err != nil {
		t.Fatal(err)
	}
	if dials(port) {
		t.Fatal("dialed after the exemption was deleted")
	}

	// An aborted transaction changes nothing.
	sentinel := errors.New("abort")
	if err := s.Transaction(func() error {
		if err := s.DeleteFilter(blockID); err != nil {
			return err
		}
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if dials(port) {
		t.Fatal("aborted delete took effect")
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !dials(port) {
		t.Fatal("filters outlived the session")
	}
	if _, err := s.AddFilter(blockPort(port)); !errors.Is(err, ErrClosed) {
		t.Errorf("closed session: %v", err)
	}
}

const childEnv = "SENTINELGO_WFP_TEST_CHILD_PORT"

// TestMain lets the crash test run this binary as a child that adds a
// block and waits to be killed.
func TestMain(m *testing.M) {
	if p := os.Getenv(childEnv); p != "" {
		os.Exit(runChild(p))
	}
	os.Exit(m.Run())
}

func runChild(p string) int {
	port, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		return 2
	}
	s, err := Open("SentinelGo wfp test child")
	if err == nil {
		err = s.AddSublayer(testSublayer, "SentinelGo wfp test", 0x100)
	}
	if err == nil {
		_, err = s.AddFilter(blockPort(uint16(port)))
	}
	if err != nil {
		fmt.Println("error:", err)
		return 1
	}
	fmt.Println("ready")
	time.Sleep(time.Minute) // killed by the parent
	return 0
}

// The filters go away when the process that added them dies.
func TestFiltersGoneAfterCrash(t *testing.T) {
	if !isAdmin() {
		t.Skip("needs an elevated process")
	}
	port := listen(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^$") // #nosec G204 -- this test binary
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%d", childEnv, port))
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line, _ := bufio.NewReader(out).ReadString('\n')
	if line != "ready\n" && line != "ready\r\n" {
		t.Fatalf("child: %q", line)
	}
	if dials(port) {
		t.Fatal("child's block not in effect")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	deadline := time.Now().Add(10 * time.Second)
	for !dials(port) {
		if time.Now().After(deadline) {
			t.Fatal("the killed process's filters stayed")
		}
		time.Sleep(200 * time.Millisecond)
	}
}
