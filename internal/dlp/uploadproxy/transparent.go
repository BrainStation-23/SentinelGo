package uploadproxy

// Transparent mode (#426 step 2, Linux): connections the nftables backstop
// redirects to the proxy arrive as plain TCP, without a CONNECT. The proxy
// reads where the client was going (the original destination, from
// conntrack) and the host it asked for (the TLS ClientHello's SNI), then:
//
//   - in scope (the SNI is an intercepted host on 443): decrypt and inspect,
//     exactly as for a CONNECT;
//   - anything else (another site sharing a CDN address, no SNI, not TLS,
//     ECH whose outer name isn't in scope): splice the bytes to the original
//     destination untouched.
//
// So a redirect by address costs other sites on the same addresses nothing
// but a hop through the proxy, unlike a block (#451).

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// OriginalDst returns where a redirected connection was going.
type OriginalDst func(net.Conn) (netip.AddrPort, error)

// Transparent mode tuning; vars for tests.
var (
	helloTimeout  = 10 * time.Second
	maxHelloBytes = 64 << 10 // a ClientHello with post-quantum key shares spans records
)

// errHelloRead stops the TLS server once it has parsed the ClientHello.
var errHelloRead = errors.New("client hello read")

// ServeTransparent accepts redirected connections on l until it is closed.
// orig reads each connection's original destination.
func (p *Proxy) ServeTransparent(l net.Listener, orig OriginalDst) error {
	for {
		c, err := l.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		go p.handleTransparent(c, orig)
	}
}

func (p *Proxy) handleTransparent(c net.Conn, orig OriginalDst) {
	dst, err := orig(c)
	if err != nil || isListener(c, dst) {
		// Not redirected: someone connected to the listener directly.
		p.errs.Add(1)
		_ = c.Close()
		return
	}
	sni, buffered := peekClientHello(c)
	port := strconv.Itoa(int(dst.Port()))
	pc := &prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(buffered), c)}
	if sni != "" && p.opts.CA != nil && p.opts.InScope(sni, port) {
		p.intercepted.Add(1)
		p.serveDecrypted(pc, sni, net.JoinHostPort(sni, port))
		return
	}
	addr := netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port()).String()
	if !p.opts.AllowLocalTargets && !allowedIP(net.IP(dst.Addr().Unmap().AsSlice())) {
		p.errs.Add(1)
		_ = c.Close()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.opts.DialTimeout)
	upstream, err := p.dialer.DialContext(ctx, "tcp", addr)
	cancel()
	if err != nil {
		p.errs.Add(1)
		_ = c.Close()
		return
	}
	p.tunnelled.Add(1)
	tunnel(c, upstream, bytes.NewReader(buffered))
}

// isListener reports whether dst is the listener the connection arrived on
// (conntrack reports that for a connection that wasn't redirected).
func isListener(c net.Conn, dst netip.AddrPort) bool {
	local, ok := c.LocalAddr().(*net.TCPAddr)
	return ok && local.AddrPort().Addr().Unmap() == dst.Addr().Unmap() && local.AddrPort().Port() == dst.Port()
}

// peekClientHello reads the client's first TLS flight far enough to parse
// its ClientHello and returns the SNI ("" when there is none, or the bytes
// aren't TLS) and every byte read, to replay. Nothing is written to the
// client.
func peekClientHello(c net.Conn) (sni string, read []byte) {
	rec := &recordingConn{Conn: c, limit: maxHelloBytes}
	_ = c.SetReadDeadline(time.Now().Add(helloTimeout))
	ctx, cancel := context.WithTimeout(context.Background(), helloTimeout)
	_ = tls.Server(rec, &tls.Config{
		// Only reading the hello: GetConfigForClient runs before any version
		// is negotiated, so this doesn't limit what can be peeked.
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = h.ServerName
			return nil, errHelloRead
		},
	}).HandshakeContext(ctx)
	cancel()
	_ = c.SetReadDeadline(time.Time{})
	return sni, rec.buf.Bytes()
}

// recordingConn keeps what is read from the client and swallows writes (the
// alert a TLS server sends when it gives up), so peeking leaves the
// connection as it was.
type recordingConn struct {
	net.Conn
	buf   bytes.Buffer
	limit int
}

func (r *recordingConn) Read(b []byte) (int, error) {
	if r.buf.Len() >= r.limit {
		return 0, errors.New("client hello too large")
	}
	if room := r.limit - r.buf.Len(); len(b) > room {
		b = b[:room]
	}
	n, err := r.Conn.Read(b)
	r.buf.Write(b[:n])
	return n, err
}

func (r *recordingConn) Write(b []byte) (int, error) { return len(b), nil }

// prefixConn replays the peeked bytes before the rest of the connection.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// CloseWrite keeps half-closes working through the wrapper.
func (c *prefixConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// logTransparentStop reports a transparent listener that stopped on its own.
func logTransparentStop(err error) {
	if err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("DLP: upload proxy transparent listener stopped: %v", err)
	}
}
