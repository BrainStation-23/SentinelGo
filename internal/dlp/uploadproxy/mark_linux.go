package uploadproxy

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// setMark puts mark on the socket (SO_MARK), so the nftables backstop lets
// the proxy's own connections through instead of redirecting them back to
// the proxy. It needs CAP_NET_ADMIN, like the nftables rules themselves: a
// proxy that can't mark can't have rules either, so a failure is ignored.
func setMark(c syscall.RawConn, mark uint32) {
	_ = c.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
	})
}
