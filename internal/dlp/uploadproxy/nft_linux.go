package uploadproxy

// Linux backstop (#426 step 2): the nftables table from nft.go, applied
// with the `nft` command, and the transparent listeners it redirects to.
//
// Unlike a WFP dynamic session, an nftables table outlives the process that
// added it. So it is removed when the block stops, on the next start after
// a crash (NewService) and on uninstall (RemoveDirectBlock).

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"sentinelgo/internal/binpath"
)

// ip6tSOOriginalDst is IP6T_SO_ORIGINAL_DST (linux/netfilter_ipv6/ip6_tables.h),
// which x/sys/unix doesn't define.
const ip6tSOOriginalDst = 80

// runNft runs an nft script; a var for tests.
var runNft = func(script string) error {
	// A fixed system path, never a PATH search: this runs as root.
	tool, ok := binpath.Lookup("nft")
	if !ok {
		return fmt.Errorf("%w: nft not found", ErrNoNft)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, "-f", "-") // #nosec G204 -- a fixed system tool; the script is built from parsed addresses and port numbers
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// platformDirectBlocker opens the nftables backstop.
var platformDirectBlocker = func(ports RedirectPorts) (DirectBlocker, error) {
	if _, ok := binpath.Lookup("nft"); !ok {
		return nil, fmt.Errorf("%w: nft not found", ErrNoNft)
	}
	return &nftBlocker{ports: ports}, nil
}

// platformDirectCleanup removes a table a crashed agent left.
var platformDirectCleanup = func() error { return removeNftTable() }

// platformTransparent listens on loopback for redirected connections: IPv4
// on 127.0.0.1 and IPv6 on ::1 (nftables redirects locally made traffic to
// the loopback address of its family). A family that can't listen gets
// port 0, and the backstop refuses its TCP instead.
var platformTransparent = func() ([]net.Listener, RedirectPorts, OriginalDst, error) {
	var ls []net.Listener
	var ports RedirectPorts
	if l, err := net.Listen("tcp4", "127.0.0.1:0"); err == nil {
		ls = append(ls, l)
		ports.V4 = uint16(l.Addr().(*net.TCPAddr).Port) // #nosec G115 -- a TCP port fits 16 bits
	}
	if l, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		ls = append(ls, l)
		ports.V6 = uint16(l.Addr().(*net.TCPAddr).Port) // #nosec G115 -- a TCP port fits 16 bits
	}
	if len(ls) == 0 {
		return nil, ports, nil, errors.New("no loopback address to listen on")
	}
	return ls, ports, originalDst, nil
}

type nftBlocker struct{ ports RedirectPorts }

func (b *nftBlocker) Set(addrs []netip.Addr, tcp bool) error {
	return runNft(nftScript(addrs, tcp, b.ports))
}

func (b *nftBlocker) Close() error { return removeNftTable() }

func (b *nftBlocker) TCPAction() string { return nftTCPAction(b.ports) }

// removeNftTable deletes the table; nothing to do without nft.
func removeNftTable() error {
	if err := runNft(nftRemoveScript()); err != nil && !errors.Is(err, ErrNoNft) {
		return err
	}
	return nil
}

// originalDst reads where a redirected connection was going from conntrack
// (SO_ORIGINAL_DST, IP6T_SO_ORIGINAL_DST). The kernel fills a sockaddr_in or
// sockaddr_in6; the x/sys getters for structs of at least that size read it
// without cgo.
func originalDst(c net.Conn) (netip.AddrPort, error) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, errors.New("not a TCP connection")
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	local, _ := tc.LocalAddr().(*net.TCPAddr)
	v6 := local != nil && local.IP.To4() == nil
	var dst netip.AddrPort
	var gerr error
	err = raw.Control(func(fd uintptr) {
		if v6 {
			// sockaddr_in6 (28 bytes) fits IPv6MTUInfo (32).
			info, e := unix.GetsockoptIPv6MTUInfo(int(fd), unix.SOL_IPV6, ip6tSOOriginalDst)
			if e != nil {
				gerr = e
				return
			}
			sa := info.Addr
			dst = netip.AddrPortFrom(netip.AddrFrom16(sa.Addr), ntohs(sa.Port))
			return
		}
		// sockaddr_in (16 bytes) fits IPv6Mreq (20).
		m, e := unix.GetsockoptIPv6Mreq(int(fd), unix.SOL_IP, unix.SO_ORIGINAL_DST)
		if e != nil {
			gerr = e
			return
		}
		b := m.Multiaddr // family(2) port(2, network order) addr(4)
		dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]}), binary.BigEndian.Uint16(b[2:4]))
	})
	if err != nil {
		return netip.AddrPort{}, err
	}
	if gerr != nil {
		return netip.AddrPort{}, gerr
	}
	return dst, nil
}

// ntohs turns a port as the kernel stored it (network order, read as a
// host-order uint16) into a number.
func ntohs(p uint16) uint16 {
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], p)
	return binary.BigEndian.Uint16(b[:])
}
