package uploadproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sentinelgo/internal/sanitize"
)

// Options configure a Proxy.
type Options struct {
	CA *CA
	// InScope reports whether connections to host:port are decrypted and
	// their uploads inspected. Everything else is tunnelled untouched. See
	// HostScope for the usual rule.
	InScope func(host, port string) bool
	// Inspector decides an upload; nil forwards everything.
	Inspector *Inspector
	// UpstreamRoots verifies the real servers; nil means the system roots.
	// Verification is never skipped.
	UpstreamRoots *x509.CertPool
	// DialTimeout bounds connecting to a server (default 15 s).
	DialTimeout time.Duration
}

// Stats are the proxy's counters.
type Stats struct {
	Tunnelled   uint64 `json:"tunnelled"`
	Intercepted uint64 `json:"intercepted"`
	Inspected   uint64 `json:"inspected"`
	Blocked     uint64 `json:"blocked"`
	Errors      uint64 `json:"errors"`
}

// Proxy is an HTTP proxy (CONNECT and absolute-URL requests) that inspects
// uploads to the hosts in scope.
type Proxy struct {
	opts      Options
	transport *http.Transport
	dialer    *net.Dialer

	tunnelled, intercepted, inspected, blocked, errs atomic.Uint64
}

// New returns a Proxy.
func New(o Options) *Proxy {
	if o.DialTimeout <= 0 {
		o.DialTimeout = 15 * time.Second
	}
	if o.InScope == nil {
		o.InScope = func(string, string) bool { return false }
	}
	d := &net.Dialer{Timeout: o.DialTimeout, KeepAlive: 30 * time.Second}
	return &Proxy{
		opts:   o,
		dialer: d,
		transport: &http.Transport{
			Proxy:               nil, // never chain to an environment proxy: no loops
			DialContext:         d.DialContext,
			TLSClientConfig:     &tls.Config{RootCAs: o.UpstreamRoots, MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 15 * time.Second,
		},
	}
}

// Stats returns the counters.
func (p *Proxy) Stats() Stats {
	return Stats{Tunnelled: p.tunnelled.Load(), Intercepted: p.intercepted.Load(), Inspected: p.inspected.Load(),
		Blocked: p.blocked.Load(), Errors: p.errs.Load()}
}

// Serve accepts proxy connections on l until it is closed.
func (p *Proxy) Serve(l net.Listener) error {
	srv := &http.Server{Handler: p, ReadHeaderTimeout: 30 * time.Second}
	return srv.Serve(l)
}

// ServeHTTP handles one proxy request.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	// A plain-HTTP request through the proxy: http://host/path.
	if r.URL.Scheme != "http" || r.URL.Host == "" {
		http.Error(w, "this is a proxy", http.StatusBadRequest)
		return
	}
	host, port := r.URL.Hostname(), r.URL.Port()
	if port == "" {
		port = "80"
	}
	p.forward(w, r, &url.URL{Scheme: "http", Host: r.URL.Host}, host, p.opts.InScope(host, port))
}

// connect handles CONNECT host:port: decrypt it when it is in scope, tunnel
// it otherwise.
func (p *Proxy) connect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		http.Error(w, "bad CONNECT target", http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "can't take over the connection", http.StatusInternalServerError)
		return
	}
	intercept := p.opts.CA != nil && p.opts.InScope(host, port)
	var upstream net.Conn
	if !intercept {
		// Connect first, so a refused connection is a proper error reply.
		if upstream, err = p.dialer.DialContext(r.Context(), "tcp", target); err != nil {
			p.errs.Add(1)
			http.Error(w, "can't reach "+host, http.StatusBadGateway)
			return
		}
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		if upstream != nil {
			_ = upstream.Close()
		}
		return
	}
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || rw.Flush() != nil {
		_ = conn.Close()
		if upstream != nil {
			_ = upstream.Close()
		}
		return
	}
	if !intercept {
		p.tunnelled.Add(1)
		tunnel(conn, upstream, rw.Reader)
		return
	}
	p.intercepted.Add(1)
	p.serveDecrypted(conn, host, target)
}

// tunnel copies bytes both ways until either side closes. buffered holds
// anything the client sent right after CONNECT.
func tunnel(client, upstream net.Conn, buffered io.Reader) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, io.MultiReader(buffered, client))
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		closeWrite(client)
	}()
	wg.Wait()
	_ = client.Close()
	_ = upstream.Close()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// serveDecrypted terminates TLS with a certificate for host and serves the
// client's requests (HTTP/1.1 or HTTP/2) on that one connection.
func (p *Proxy) serveDecrypted(conn net.Conn, host, target string) {
	tlsConn := tls.Server(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// The certificate is for the CONNECT host, whatever SNI says.
			return p.opts.CA.Leaf(host)
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	err := tlsConn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		// A client that doesn't trust the CA, or a pinned app: nothing to do.
		p.errs.Add(1)
		_ = tlsConn.Close()
		return
	}
	upstream := &url.URL{Scheme: "https", Host: target}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h := r.Host; h != "" && !sameHost(h, host) {
			http.Error(w, "request host doesn't match the connection", http.StatusBadRequest)
			return
		}
		p.forward(w, r, upstream, host, true)
	})
	l := newOneConnListener(tlsConn)
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 30 * time.Second,
		ConnState: func(_ net.Conn, s http.ConnState) {
			if s == http.StateClosed || s == http.StateHijacked {
				l.done()
			}
		}}
	_ = srv.Serve(l)
}

// HostScope is the usual scope: the listed hosts (exactly, or "*.example.com"
// for subdomains), on HTTPS (443) and HTTP (80) only.
func HostScope(hosts []string) func(host, port string) bool {
	exact, suffixes := map[string]bool{}, []string{}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		switch {
		case h == "":
		case strings.HasPrefix(h, "*."):
			suffixes = append(suffixes, h[1:])
		default:
			exact[h] = true
		}
	}
	return func(host, port string) bool {
		if port != "443" && port != "80" {
			return false
		}
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if exact[host] {
			return true
		}
		for _, s := range suffixes {
			if strings.HasSuffix(host, s) {
				return true
			}
		}
		return false
	}
}

// sameHost compares a Host header (maybe with a port) with a host name.
func sameHost(hostHeader, host string) bool {
	h := hostHeader
	if hh, _, err := net.SplitHostPort(hostHeader); err == nil {
		h = hh
	}
	return strings.EqualFold(strings.Trim(h, "[]"), strings.Trim(host, "[]"))
}

// forward inspects an upload (when inspect is true) and sends the request to
// upstream, or refuses it.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, upstream *url.URL, host string, inspect bool) {
	if inspect && p.opts.Inspector != nil && hasBody(r) {
		p.inspected.Add(1)
		v, body, err := p.opts.Inspector.Inspect(r.Context(), r, host)
		if err != nil {
			p.errs.Add(1)
			http.Error(w, "upload inspection failed", http.StatusBadGateway)
			return
		}
		defer func() { _ = body.Close() }()
		if v.Block {
			p.blocked.Add(1)
			log.Printf("DLP: blocked an upload to %s", sanitize.ForLog(host)) // #nosec G706 -- the client-supplied host has its line breaks removed (sanitize.ForLog)
			http.Error(w, v.Message, http.StatusForbidden)
			return
		}
		r.Body = body
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			pr.Out.Host = pr.In.Host
		},
		Transport: p.transport,
		// Includes a real server whose certificate isn't trusted: the request
		// is never sent.
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			p.errs.Add(1)
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}

// hasBody reports whether r may carry an upload.
func hasBody(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0
	}
	return false
}

// oneConnListener hands one connection to an http.Server, then blocks Accept
// until that connection is done.
type oneConnListener struct {
	conn     net.Conn
	once     sync.Once
	accepted atomic.Bool
	closed   chan struct{}
}

func newOneConnListener(c net.Conn) *oneConnListener {
	return &oneConnListener{conn: c, closed: make(chan struct{})}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	if l.accepted.CompareAndSwap(false, true) {
		return l.conn, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *oneConnListener) done()          { l.once.Do(func() { close(l.closed) }) }
func (l *oneConnListener) Close() error   { l.done(); return nil }
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
