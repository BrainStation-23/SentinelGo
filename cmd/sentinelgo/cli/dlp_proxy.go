package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"sentinelgo/internal/config"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/filedlp"
	"sentinelgo/internal/dlp/policy"
	"sentinelgo/internal/dlp/uploadproxy"
)

// uploadSpillDir holds upload bodies while they are inspected (config dir).
const uploadSpillDir = "upload-spill"

// runDLPProxy is `sentinelgo dlp proxy`: the upload inspection proxy (#344,
// phase 1) run by hand for testing. Point a browser at it as its HTTP and
// HTTPS proxy and trust the CA it exports; uploads to -hosts are inspected
// with the cached policy's file.upload channel, everything else is
// tunnelled. Events are printed as JSON lines instead of being queued.
func runDLPProxy(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("dlp proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "config.json of the install (default: the standard path)")
	listen := fs.String("listen", "127.0.0.1:3129", "loopback address to listen on")
	hosts := fs.String("hosts", "", "comma-separated hosts to inspect (*.example.com for subdomains)")
	caOut := fs.String("ca-out", "", "write the inspection CA certificate (PEM) here, to install in the browser")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	scope := strings.Split(*hosts, ",")
	if strings.TrimSpace(*hosts) == "" {
		_, _ = fmt.Fprintln(stderr, "-hosts is required: the destinations to inspect")
		return 2
	}
	if err := requireLoopback(*listen); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	load := loadDefaultConfig
	if *cfgPath != "" {
		load = func() (*config.Config, error) { return config.Load(*cfgPath) }
	}
	cfg, err := load()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Failed to load config: %v\n", err)
		return 1
	}
	dir := dlpDir(cfg)
	b, err := policy.NewCache(filepath.Join(dir, policy.CacheFileName)).Load()
	if err != nil || b == nil {
		_, _ = fmt.Fprintf(stderr, "No cached DLP policy (%v): the proxy needs one\n", err)
		return 1
	}
	c := policy.Compile(b)
	if !c.ChannelEnabled(policy.ChannelFileUpload) {
		_, _ = fmt.Fprintln(stderr, "Warning: file.upload is off in the cached policy: uploads are forwarded without inspection")
	}
	ca, err := uploadproxy.LoadOrCreateCA(dir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Inspection CA: %v\n", err)
		return 1
	}
	if *caOut != "" {
		if err := os.WriteFile(*caOut, ca.CertPEM(), 0o644); err != nil { // #nosec G306 -- a public certificate
			_, _ = fmt.Fprintf(stderr, "Write CA: %v\n", err)
			return 1
		}
	}
	spill := filepath.Join(dir, uploadSpillDir)
	if err := resetDir(spill); err != nil {
		_, _ = fmt.Fprintf(stderr, "Spill directory: %v\n", err)
		return 1
	}
	raw, _ := json.Marshal(b)
	scanner, stopScanner, warning := newProxyScanner(c, raw, spill)
	defer stopScanner()
	if warning != "" {
		_, _ = fmt.Fprintln(stderr, "Warning: "+warning)
	}
	d := filedlp.NewDecider(scanner, &jsonLines{w: stdout})
	d.Apply(c)
	p := uploadproxy.New(uploadproxy.Options{CA: ca, InScope: uploadproxy.HostScope(scope), Inspector: uploadproxy.NewInspector(d, spill)})
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Listen: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stderr, "Upload proxy on %s, inspecting %s. Set it as the browser's HTTP and HTTPS proxy and trust %s.\n",
		l.Addr(), strings.Join(scope, ", "), filepath.Join(dir, uploadproxy.CACertFile))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); _ = l.Close() }()
	if err := p.Serve(l); err != nil && !errors.Is(err, net.ErrClosed) {
		_, _ = fmt.Fprintf(stderr, "Serve: %v\n", err)
	}
	st, _ := json.Marshal(p.Stats())
	_, _ = fmt.Fprintf(stderr, "Stopped: %s\n", st)
	return 0
}

// requireLoopback refuses anything but a loopback address: the proxy must
// never be reachable from the network.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("-listen %q: %v", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("-listen %q: only a loopback address is allowed (e.g. 127.0.0.1:3129)", addr)
	}
	return nil
}

// resetDir creates dir (owner only) and empties it of spill files a crash
// may have left.
func resetDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
	return nil
}

// jsonLines prints events as JSON lines.
type jsonLines struct {
	mu sync.Mutex
	w  io.Writer
}

func (j *jsonLines) Emit(ev events.Event) {
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	_, _ = fmt.Fprintln(j.w, string(b))
}
