//go:build windows && (amd64 || arm64)

package uploadproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"sentinelgo/internal/wfp"
)

// directSublayer holds the agent's upload inspection filters. Its weight
// puts it before the default sublayers; a security product's hard permit
// in a heavier sublayer still wins (lab pass, #429).
var directSublayer = windows.GUID{Data1: 0x8f3b9a61, Data2: 0x2c4e, Data3: 0x4b7d, Data4: [8]byte{0xa1, 0x5e, 0x63, 0x0d, 0x94, 0x2f, 0x7c, 0x18}}

const directSublayerWeight = 0x7000

// Filter weights in the sublayer: the agent's own permit beats the block.
const (
	weightPermitSelf = 15
	weightBlock      = 1
)

// platformDirectBlocker opens the WFP blocker. Windows has no transparent
// redirect (that needs a callout driver), so strict refuses TCP.
var platformDirectBlocker = func(RedirectPorts) (DirectBlocker, error) { return newWFPBlocker() }

// platformDirectCleanup: the filters live in a dynamic session, which
// Windows removes when the agent dies.
var platformDirectCleanup func() error

// platformTransparent: no transparent redirect on Windows.
var platformTransparent func() ([]net.Listener, RedirectPorts, OriginalDst, error)

// platformResolver asks the Windows DNS client, which reports TTLs.
var platformResolver Resolver = dnsResolve

type wfpBlocker struct {
	s   *wfp.Session
	ids []uint64 // the block filters
}

func newWFPBlocker() (*wfpBlocker, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	appID, err := wfp.AppID(exe)
	if err != nil {
		return nil, err
	}
	s, err := wfp.Open("SentinelGo upload inspection")
	if err != nil {
		return nil, err
	}
	err = s.Transaction(func() error {
		if err := s.AddSublayer(directSublayer, "SentinelGo upload inspection", directSublayerWeight); err != nil {
			return err
		}
		for _, layer := range []windows.GUID{wfp.LayerALEAuthConnectV4, wfp.LayerALEAuthConnectV6} {
			if _, err := s.AddFilter(wfp.Filter{Name: "SentinelGo: the upload proxy's own connections", Layer: layer,
				Sublayer: directSublayer, Weight: weightPermitSelf, Action: wfp.Permit,
				Conditions: []wfp.Condition{{Field: wfp.FieldALEAppID, Value: wfp.AppIDValue(appID)}}}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	return &wfpBlocker{s: s}, nil
}

// Set swaps the block filters in one transaction: one filter per address
// family, matching any of the addresses (conditions on one field are ORed)
// on port 443 over UDP, or TCP or UDP when tcp is set (strict, #451).
func (b *wfpBlocker) Set(addrs []netip.Addr, tcp bool) error {
	protocols := []wfp.Condition{{Field: wfp.FieldIPProtocol, Value: wfp.Uint8(wfp.ProtocolUDP)}}
	name := "SentinelGo: QUIC to inspected sites"
	if tcp {
		protocols = append(protocols, wfp.Condition{Field: wfp.FieldIPProtocol, Value: wfp.Uint8(wfp.ProtocolTCP)})
		name = "SentinelGo: direct uploads to inspected sites"
	}
	var v4, v6 []wfp.Condition
	for _, a := range addrs {
		c := wfp.Condition{Field: wfp.FieldIPRemoteAddress, Value: wfp.Prefix(netip.PrefixFrom(a, a.BitLen()))}
		if a.Is4() {
			v4 = append(v4, c)
		} else {
			v6 = append(v6, c)
		}
	}
	var ids []uint64
	err := b.s.Transaction(func() error {
		for _, id := range b.ids {
			if err := b.s.DeleteFilter(id); err != nil {
				return err
			}
		}
		for _, f := range []struct {
			layer windows.GUID
			conds []wfp.Condition
		}{{wfp.LayerALEAuthConnectV4, v4}, {wfp.LayerALEAuthConnectV6, v6}} {
			if len(f.conds) == 0 {
				continue
			}
			conds := slices.Concat(f.conds,
				[]wfp.Condition{{Field: wfp.FieldIPRemotePort, Value: wfp.Uint16(443)}}, protocols)
			id, err := b.s.AddFilter(wfp.Filter{Name: name, Layer: f.layer,
				Sublayer: directSublayer, Weight: weightBlock, Action: wfp.Block, Conditions: conds})
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
	b.ids = ids
	return nil
}

func (b *wfpBlocker) Close() error { return b.s.Close() }

// DNS record types and DnsQuery results.
const (
	dnsTypeA          = 1
	dnsTypeAAAA       = 28
	dnsFreeRecordList = 1
	dnsErrorNameError = 9003 // DNS_ERROR_RCODE_NAME_ERROR
	dnsInfoNoRecords  = 9501 // DNS_INFO_NO_RECORDS
)

// dnsResolve resolves host's A and AAAA records through the DNS client
// (and its cache), with the smallest TTL among them.
func dnsResolve(ctx context.Context, host string) ([]netip.Addr, time.Duration, error) {
	type result struct {
		addrs []netip.Addr
		ttl   time.Duration
		err   error
	}
	ch := make(chan result, 1)
	go func() { // DnsQuery can't be cancelled; the caller doesn't wait past ctx
		var r result
		r.ttl = maxDNSTTL
		var errs []error
		for _, qt := range []uint16{dnsTypeA, dnsTypeAAAA} {
			addrs, ttl, err := dnsQuery(host, qt)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			r.addrs = append(r.addrs, addrs...)
			if len(addrs) > 0 {
				r.ttl = min(r.ttl, ttl)
			}
		}
		if len(r.addrs) == 0 && len(errs) > 0 {
			r.err = errors.Join(errs...)
		}
		ch <- r
	}()
	select {
	case r := <-ch:
		return r.addrs, r.ttl, r.err
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	}
}

func dnsQuery(host string, qtype uint16) ([]netip.Addr, time.Duration, error) {
	var rec *windows.DNSRecord
	err := windows.DnsQuery(host, qtype, 0, nil, &rec, nil)
	if errors.Is(err, windows.Errno(dnsErrorNameError)) || errors.Is(err, windows.Errno(dnsInfoNoRecords)) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("DnsQuery %s type %d: %w", host, qtype, err)
	}
	defer windows.DnsRecordListFree(rec, dnsFreeRecordList)
	var addrs []netip.Addr
	ttl := maxDNSTTL
	for r := rec; r != nil; r = r.Next {
		if r.Type != qtype { // CNAMEs on the way
			continue
		}
		switch qtype {
		case dnsTypeA:
			addrs = append(addrs, netip.AddrFrom4(*(*[4]byte)(unsafe.Pointer(&r.Data[0]))))
		case dnsTypeAAAA:
			addrs = append(addrs, netip.AddrFrom16(*(*[16]byte)(unsafe.Pointer(&r.Data[0]))))
		}
		ttl = min(ttl, time.Duration(r.Ttl)*time.Second)
	}
	return addrs, ttl, nil
}
