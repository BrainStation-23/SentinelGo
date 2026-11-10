//go:build windows && (amd64 || arm64)

package wfp

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	fwpuclnt                      = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0           = fwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0          = fwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmSubLayerAdd0          = fwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmFilterAdd0            = fwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteByID0     = fwpuclnt.NewProc("FwpmFilterDeleteById0")
	procFwpmTransactionBegin0     = fwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0    = fwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0     = fwpuclnt.NewProc("FwpmTransactionAbort0")
	procFwpmGetAppIDFromFileName0 = fwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
	procFwpmFreeMemory0           = fwpuclnt.NewProc("FwpmFreeMemory0")
)

// Layers and condition fields (fwpmu.h, Windows SDK 10.0.26100).
var (
	LayerALEAuthConnectV4 = windows.GUID{Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33, Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}
	LayerALEAuthConnectV6 = windows.GUID{Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc, Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}

	FieldIPRemoteAddress = windows.GUID{Data1: 0xb235ae9a, Data2: 0x1d64, Data3: 0x49b8, Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}}
	FieldIPRemotePort    = windows.GUID{Data1: 0xc35a604d, Data2: 0xd22b, Data3: 0x4e1a, Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}}
	FieldIPProtocol      = windows.GUID{Data1: 0x3971ef2b, Data2: 0x623e, Data3: 0x4f9a, Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}}
	FieldALEAppID        = windows.GUID{Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4ea5, Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}}
)

// IP protocol numbers for FieldIPProtocol.
const (
	ProtocolTCP = 6
	ProtocolUDP = 17
)

// Action is what a filter does with a match.
type Action uint32

// Actions (fwptypes.h: the type ORed with FWP_ACTION_FLAG_TERMINATING).
const (
	Block  Action = 0x1001
	Permit Action = 0x1002
)

// Match is how a condition compares (FWP_MATCH_TYPE).
type Match uint32

// Matches.
const (
	MatchEqual    Match = 0
	MatchNotEqual Match = 10
)

// FWP_DATA_TYPE values the agent uses.
const (
	typeEmpty      = 0
	typeUint8      = 1
	typeUint16     = 2
	typeByteBlob   = 12
	typeV4AddrMask = 0x100
	typeV6AddrMask = 0x101
)

const (
	sessionFlagDynamic = 0x00000001
	rpcCAuthnWinNT     = 10
)

// Value is a condition's value. Build it with Uint8, Uint16, Prefix or
// AppIDValue.
type Value struct {
	typ   uint32
	small uint64
	v4    *v4AddrAndMask
	v6    *v6AddrAndMask
	blob  []byte
}

// Uint8 is an 8-bit value (an IP protocol number).
func Uint8(v uint8) Value { return Value{typ: typeUint8, small: uint64(v)} }

// Uint16 is a 16-bit value (a port).
func Uint16(v uint16) Value { return Value{typ: typeUint16, small: uint64(v)} }

// Prefix is an IPv4 or IPv6 address range; a single address is a /32 or
// /128. The prefix must be valid.
func Prefix(p netip.Prefix) Value {
	p = p.Masked()
	if p.Addr().Is4() {
		a := p.Addr().As4()
		bits := p.Bits()
		var mask uint32
		if bits > 0 {
			mask = ^uint32(0) << (32 - bits)
		}
		// Host byte order, as WFP takes IPv4 addresses.
		return Value{typ: typeV4AddrMask, v4: &v4AddrAndMask{addr: uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3]), mask: mask}}
	}
	return Value{typ: typeV6AddrMask, v6: &v6AddrAndMask{addr: p.Addr().As16(), prefixLength: uint8(p.Bits())}} // #nosec G115 -- 0..128
}

// AppIDValue is an application id from AppID.
func AppIDValue(id []byte) Value { return Value{typ: typeByteBlob, blob: id} }

// Condition is one test of a filter. Conditions on the same field are ORed,
// on different fields ANDed.
type Condition struct {
	Field windows.GUID
	Match Match
	Value Value
}

// Filter is a rule added to a sublayer.
type Filter struct {
	Name       string
	Layer      windows.GUID
	Sublayer   windows.GUID
	Weight     uint8 // 0..15; within the sublayer the highest matching weight decides
	Action     Action
	Conditions []Condition
}

// C layouts (fwpmtypes.h, fwptypes.h), identical on amd64 and arm64; sizes
// and offsets are asserted below and in the tests.

type displayData0 struct {
	name        *uint16
	description *uint16
}

type byteBlob struct {
	size uint32
	data *byte
}

type session0 struct {
	sessionKey           windows.GUID
	displayData          displayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processID            uint32
	sid                  *windows.SID
	username             *uint16
	kernelMode           int32
}

type sublayer0 struct {
	subLayerKey  windows.GUID
	displayData  displayData0
	flags        uint32
	providerKey  *windows.GUID
	providerData byteBlob
	weight       uint16
}

// value0 is FWP_VALUE0 and FWP_CONDITION_VALUE0: a type and an 8-byte union
// holding a small integer or a pointer. Pointers are kept as uintptr (an
// integer in the union isn't a valid Go pointer); what they point to is
// kept alive by the caller until the call returns.
type value0 struct {
	typ uint32
	val uintptr
}

type filterCondition0 struct {
	fieldKey       windows.GUID
	matchType      uint32
	conditionValue value0
}

type action0 struct {
	typ        uint32
	filterType windows.GUID
}

type filter0 struct {
	filterKey           windows.GUID
	displayData         displayData0
	flags               uint32
	providerKey         *windows.GUID
	providerData        byteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              value0
	numFilterConditions uint32
	filterCondition     *filterCondition0
	action              action0
	rawContext          uint64  // union with providerContextKey (a GUID)
	_                   [8]byte // the rest of that union
	reserved            *windows.GUID
	filterID            uint64
	effectiveWeight     value0
}

type v4AddrAndMask struct {
	addr uint32
	mask uint32
}

type v6AddrAndMask struct {
	addr         [16]byte
	prefixLength uint8
}

// Compile-time size checks against the Windows SDK (also on arm64 through
// make verify-cross): a wrong size makes an array length negative.
var (
	_ [unsafe.Sizeof(session0{}) - 72]byte
	_ [72 - unsafe.Sizeof(session0{})]byte
	_ [unsafe.Sizeof(sublayer0{}) - 72]byte
	_ [72 - unsafe.Sizeof(sublayer0{})]byte
	_ [unsafe.Sizeof(filterCondition0{}) - 40]byte
	_ [40 - unsafe.Sizeof(filterCondition0{})]byte
	_ [unsafe.Sizeof(filter0{}) - 200]byte
	_ [200 - unsafe.Sizeof(filter0{})]byte
	_ [unsafe.Sizeof(value0{}) - 16]byte
	_ [16 - unsafe.Sizeof(value0{})]byte
	_ [unsafe.Sizeof(v6AddrAndMask{}) - 17]byte
	_ [17 - unsafe.Sizeof(v6AddrAndMask{})]byte
)

// Error is a WFP error code (FWP_E_*, 0x8032xxxx).
type Error uint32

func (e Error) Error() string { return fmt.Sprintf("wfp error 0x%08x", uint32(e)) }

// ErrAlreadyExists is FWP_E_ALREADY_EXISTS (an object with that key).
const ErrAlreadyExists Error = 0x80320009

// errorFrom turns a WFP return code into an error: nil for 0, a Win32
// errno (so errors.Is(err, windows.ERROR_ACCESS_DENIED) works) or an Error.
func errorFrom(r uintptr) error {
	switch {
	case r == 0:
		return nil
	case r < 0x10000:
		return windows.Errno(r)
	}
	return Error(r)
}

func call(p *windows.LazyProc, args ...uintptr) error {
	if err := p.Find(); err != nil {
		return err
	}
	r, _, _ := p.Call(args...)
	return errorFrom(r)
}

// Session is an open, dynamic WFP engine session. It is safe for
// concurrent use; Close removes everything added through it.
type Session struct {
	mu sync.Mutex
	h  windows.Handle
}

// Open opens a dynamic session named name. It needs administrator rights to
// add filters.
func Open(name string) (*Session, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	s := &session0{displayData: displayData0{name: n}, flags: sessionFlagDynamic}
	var h windows.Handle
	if err := call(procFwpmEngineOpen0, 0, rpcCAuthnWinNT, 0, uintptr(unsafe.Pointer(s)), uintptr(unsafe.Pointer(&h))); err != nil {
		return nil, fmt.Errorf("FwpmEngineOpen0: %w", err)
	}
	return &Session{h: h}, nil
}

// ErrClosed is returned by a closed Session.
var ErrClosed = errors.New("wfp: session closed")

// Close closes the session; WFP removes its sublayers and filters.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.h == 0 {
		return nil
	}
	err := call(procFwpmEngineClose0, uintptr(s.h))
	s.h = 0
	if err != nil {
		return fmt.Errorf("FwpmEngineClose0: %w", err)
	}
	return nil
}

func (s *Session) handle() (windows.Handle, error) {
	if s.h == 0 {
		return 0, ErrClosed
	}
	return s.h, nil
}

// AddSublayer adds a sublayer with the given key. weight orders it among
// the other sublayers (higher is evaluated first); a block in any sublayer
// overrides a permit in another, unless that permit is a hard one.
func (s *Session) AddSublayer(key windows.GUID, name string, weight uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.handle()
	if err != nil {
		return err
	}
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	sl := &sublayer0{subLayerKey: key, displayData: displayData0{name: n}, weight: weight}
	if err := call(procFwpmSubLayerAdd0, uintptr(h), uintptr(unsafe.Pointer(sl)), 0); err != nil {
		return fmt.Errorf("FwpmSubLayerAdd0: %w", err)
	}
	return nil
}

// AddFilter adds f and returns its id.
func (s *Session) AddFilter(f Filter) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.handle()
	if err != nil {
		return 0, err
	}
	c, keep, err := f.marshal()
	if err != nil {
		return 0, err
	}
	var id uint64
	err = call(procFwpmFilterAdd0, uintptr(h), uintptr(unsafe.Pointer(c)), 0, uintptr(unsafe.Pointer(&id)))
	runtime.KeepAlive(keep)
	runtime.KeepAlive(c)
	if err != nil {
		return 0, fmt.Errorf("FwpmFilterAdd0 %q: %w", f.Name, err)
	}
	return id, nil
}

// DeleteFilter removes the filter with id.
func (s *Session) DeleteFilter(id uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.handle()
	if err != nil {
		return err
	}
	if err := call(procFwpmFilterDeleteByID0, uintptr(h), uintptr(id)); err != nil {
		return fmt.Errorf("FwpmFilterDeleteById0: %w", err)
	}
	return nil
}

// Transaction runs fn in a WFP transaction: everything fn adds or deletes
// takes effect together when it returns nil, and not at all otherwise.
// fn uses the Session's own methods.
func (s *Session) Transaction(fn func() error) error {
	s.mu.Lock()
	h, err := s.handle()
	if err == nil {
		err = call(procFwpmTransactionBegin0, uintptr(h), 0)
	}
	s.mu.Unlock()
	if err != nil {
		return fmt.Errorf("FwpmTransactionBegin0: %w", err)
	}
	if err := fn(); err != nil {
		s.mu.Lock()
		if s.h != 0 {
			_ = call(procFwpmTransactionAbort0, uintptr(s.h))
		}
		s.mu.Unlock()
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if h, err = s.handle(); err != nil {
		return err
	}
	if err := call(procFwpmTransactionCommit0, uintptr(h)); err != nil {
		return fmt.Errorf("FwpmTransactionCommit0: %w", err)
	}
	return nil
}

// AppID returns the WFP application id of the program at path (its NT
// path, as FieldALEAppID compares it).
func AppID(path string) ([]byte, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var blob *byteBlob
	if err := call(procFwpmGetAppIDFromFileName0, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&blob))); err != nil {
		return nil, fmt.Errorf("FwpmGetAppIdFromFileName0: %w", err)
	}
	defer func() { _ = call(procFwpmFreeMemory0, uintptr(unsafe.Pointer(&blob))) }()
	if blob == nil || blob.data == nil || blob.size == 0 {
		return nil, errors.New("FwpmGetAppIdFromFileName0: empty app id")
	}
	return append([]byte(nil), unsafe.Slice(blob.data, blob.size)...), nil
}

// marshal lays f out as an FWPM_FILTER0. keep holds everything the
// struct's uintptr fields point to, for the caller to keep alive over the
// call.
func (f Filter) marshal() (*filter0, []any, error) {
	if f.Weight > 15 {
		return nil, nil, fmt.Errorf("wfp: filter weight %d over 15", f.Weight)
	}
	if f.Action != Block && f.Action != Permit {
		return nil, nil, fmt.Errorf("wfp: unknown action %#x", uint32(f.Action))
	}
	name, err := windows.UTF16PtrFromString(f.Name)
	if err != nil {
		return nil, nil, err
	}
	keep := []any{name}
	c := &filter0{
		displayData: displayData0{name: name},
		layerKey:    f.Layer,
		subLayerKey: f.Sublayer,
		weight:      value0{typ: typeUint8, val: uintptr(f.Weight)},
		action:      action0{typ: uint32(f.Action)},
	}
	if n := len(f.Conditions); n > 0 {
		conds := make([]filterCondition0, n)
		for i, cond := range f.Conditions {
			v, k, err := cond.Value.marshal()
			if err != nil {
				return nil, nil, err
			}
			keep = append(keep, k)
			conds[i] = filterCondition0{fieldKey: cond.Field, matchType: uint32(cond.Match), conditionValue: v}
		}
		keep = append(keep, conds)
		c.numFilterConditions = uint32(n) // #nosec G115 -- a filter has far fewer than 4G conditions
		c.filterCondition = &conds[0]
	}
	return c, keep, nil
}

// marshal lays v out as an FWP_CONDITION_VALUE0; keep is what its pointer
// points to.
func (v Value) marshal() (value0, any, error) {
	switch v.typ {
	case typeUint8, typeUint16:
		return value0{typ: v.typ, val: uintptr(v.small)}, nil, nil
	case typeV4AddrMask:
		return value0{typ: v.typ, val: uintptr(unsafe.Pointer(v.v4))}, v.v4, nil
	case typeV6AddrMask:
		return value0{typ: v.typ, val: uintptr(unsafe.Pointer(v.v6))}, v.v6, nil
	case typeByteBlob:
		if len(v.blob) == 0 {
			return value0{}, nil, errors.New("wfp: empty byte blob")
		}
		b := &byteBlob{size: uint32(len(v.blob)), data: &v.blob[0]} // #nosec G115 -- an app id is a path
		return value0{typ: v.typ, val: uintptr(unsafe.Pointer(b))}, b, nil
	case typeEmpty:
		return value0{}, nil, errors.New("wfp: empty condition value")
	}
	return value0{}, nil, fmt.Errorf("wfp: unknown value type %d", v.typ)
}
