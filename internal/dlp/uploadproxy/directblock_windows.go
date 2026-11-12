//go:build windows && (amd64 || arm64)

package uploadproxy

import (
	"net"
	"net/netip"
	"os"
	"slices"

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
