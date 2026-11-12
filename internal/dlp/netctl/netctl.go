// Package netctl applies the file DLP network controls (#427, contract
// proposed on Compliance-OS#910): apps admins mark as unsanctioned get no
// network access except to the allowed destinations. Windows only, through
// WFP filters in a dynamic session (they go when the agent dies); other OSes
// report the controls as unsupported.
//
// It is enforcement, so nothing is blocked while the files module is
// audit_only: the status then says what would be blocked.
package netctl

import (
	"context"
	"log"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"sentinelgo/internal/dlp/addrbook"
	"sentinelgo/internal/dlp/policy"
)

// Ruleset is the OS firewall the controls are applied with.
type Ruleset interface {
	// Set replaces the rules: block every outbound connection from the
	// executables in Rules.BlockApps, except to Rules.Allow.
	Set(r Rules) error
	// Close removes every rule.
	Close() error
}

// Rules are what the Ruleset enforces.
type Rules struct {
	BlockApps []string       // executable paths
	Allow     []netip.Prefix // always reachable (loopback is added by the Ruleset)
}

// States in the status.
const (
	StateActive    = "active"
	StateInactive  = "inactive"
	StateAuditOnly = "off:audit_only"
	StatePolicyOff = "off:policy"
)

// Capability names in the DLP status's capabilities.
const (
	CapBlockedApps = "network_control.blocked_apps"
	CapTaintBlock  = "network_control.taint_block"
)

// Status is files.network_control in the DLP status report.
type Status struct {
	State             string      `json:"state"`
	BlockedApps       AppsStatus  `json:"blocked_apps"`
	AllowDestinations AllowStatus `json:"allow_destinations"`
}

// AppsStatus says which blocked apps are applied (or would be, in audit
// only).
type AppsStatus struct {
	Applied    int          `json:"applied"` // executables
	NotApplied []NotApplied `json:"not_applied,omitempty"`
}

// NotApplied is a blocked app that isn't applied, and why.
type NotApplied struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// AllowStatus counts the allowed destinations' addresses.
type AllowStatus struct {
	Addresses  int `json:"addresses"`  // resolved host addresses plus ranges
	Unresolved int `json:"unresolved"` // hosts without an address yet
	Patterns   int `json:"patterns"`   // "*." patterns, which can't be resolved
}

// Options configure a Controller; zero values mean this OS's.
type Options struct {
	Open    func() (Ruleset, error)
	Resolve addrbook.Resolver
	// Env are the environment variables for %VAR% (lower-case names), and
	// Profiles the local user profile folders, for the per-user ones.
	Env      func() map[string]string
	Profiles func() []string
	// Exists reports whether an executable is installed.
	Exists func(path string) bool
	GOOS   string
}

// refreshEvery re-resolves the allowed hosts and looks for apps installed
// since; a var for tests.
var refreshEvery = 30 * time.Second

// Controller keeps the Ruleset in step with the policy.
type Controller struct {
	opts Options

	mu       sync.Mutex
	compiled *policy.Compiled
	rules    Ruleset
	applied  *Rules
	openErr  string
	book     *addrbook.Book
	st       Status
	cancel   context.CancelFunc
	done     chan struct{}
}

// New returns a Controller.
func New(o Options) *Controller {
	if o.Open == nil {
		o.Open = platformOpen
	}
	if o.Resolve == nil {
		o.Resolve = addrbook.System
	}
	if o.Env == nil {
		o.Env = platformEnv
	}
	if o.Profiles == nil {
		o.Profiles = platformProfiles
	}
	if o.Exists == nil {
		o.Exists = platformExists
	}
	if o.GOOS == "" {
		o.GOOS = runtime.GOOS
	}
	return &Controller{opts: o, book: addrbook.New(o.Resolve), st: Status{State: StateInactive}}
}

// Supported reports whether this OS can apply the controls.
func (c *Controller) Supported() bool { return c.opts.GOOS == "windows" && c.opts.Open != nil }

// Wants reports whether m turns a control on that this OS applies.
func (c *Controller) Wants(m policy.FilesModule) bool {
	return c.Supported() && len(m.NetworkControl.BlockedApps[c.opts.GOOS]) > 0 && m.ControlsNetwork(c.opts.GOOS)
}

// Apply switches to cp.
func (c *Controller) Apply(_ context.Context, cp *policy.Compiled) {
	c.mu.Lock()
	c.compiled = cp
	running := c.cancel != nil
	want := cp != nil && c.Wants(cp.Modules.Files)
	c.mu.Unlock()
	switch {
	case want && !running:
		c.start()
	case !want && running:
		c.Stop()
	}
	c.sync(context.Background())
}

func (c *Controller) start() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	c.mu.Lock()
	c.cancel, c.done = cancel, done
	c.mu.Unlock()
	go func() {
		defer close(done)
		t := time.NewTicker(refreshEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				c.sync(ctx)
			}
		}
	}()
}

// Stop removes every rule and stops refreshing.
func (c *Controller) Stop() {
	c.mu.Lock()
	cancel, done := c.cancel, c.done
	c.cancel, c.done = nil, nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
	c.st = Status{State: StateInactive}
}

func (c *Controller) closeLocked() {
	if c.rules != nil {
		if err := c.rules.Close(); err != nil {
			log.Printf("DLP: network controls: remove the rules: %v", err)
		}
		c.rules, c.applied = nil, nil
	}
}

// sync works out the rules for the current policy and applies them.
func (c *Controller) sync(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := c.compiled
	if cp == nil || !c.Supported() || !cp.Modules.Files.ControlsNetwork(c.opts.GOOS) ||
		len(cp.Modules.Files.NetworkControl.BlockedApps[c.opts.GOOS]) == 0 {
		c.closeLocked()
		state := StateInactive
		if cp != nil && cp.Modules.Files.Enabled && !cp.Modules.Files.NetworkControl.Enabled {
			state = StatePolicyOff
		}
		c.st = Status{State: state}
		return
	}
	m := cp.Modules.Files
	rules, apps := c.wantedLocked(m)
	allow := c.allowLocked(ctx, m.NetworkControl)
	rules.Allow = allow.ranges
	c.st = Status{BlockedApps: apps, AllowDestinations: allow.status}
	if m.IsAuditOnly() {
		c.closeLocked()
		c.st.State = StateAuditOnly
		return
	}
	if c.rules == nil {
		r, err := c.opts.Open()
		if err != nil {
			c.openErr = "wfp_error"
			c.st.State = "unsupported:" + c.openErr
			log.Printf("DLP: network controls: %v", err)
			return
		}
		c.rules, c.applied, c.openErr = r, nil, ""
	}
	if c.applied == nil || !sameRules(*c.applied, rules) {
		if err := c.rules.Set(rules); err != nil {
			log.Printf("DLP: network controls: apply the rules: %v", err)
			c.closeLocked()
			c.st.State = "unsupported:wfp_error"
			return
		}
		c.applied = &rules
	}
	c.st.State = StateActive
}

// wantedLocked expands the blocked apps into executables.
func (c *Controller) wantedLocked(m policy.FilesModule) (Rules, AppsStatus) {
	env, profiles := c.opts.Env(), c.opts.Profiles()
	var r Rules
	var st AppsStatus
	seen := map[string]bool{}
	for _, a := range m.NetworkControl.BlockedApps[c.opts.GOOS] {
		paths, reason := expandApp(a, env, profiles)
		found := false
		for _, p := range paths {
			key := strings.ToLower(p)
			if !c.opts.Exists(p) {
				continue
			}
			found = true
			if !seen[key] {
				seen[key] = true
				r.BlockApps = append(r.BlockApps, p)
			}
		}
		if reason == "" && !found {
			reason = ReasonPathNotFound
		}
		if reason != "" {
			st.NotApplied = append(st.NotApplied, NotApplied{Name: appName(a), Reason: reason})
		}
	}
	slices.SortFunc(r.BlockApps, func(a, b string) int { return strings.Compare(strings.ToLower(a), strings.ToLower(b)) })
	st.Applied = len(r.BlockApps)
	return r, st
}

type allowed struct {
	ranges []netip.Prefix
	status AllowStatus
}

// allowLocked resolves the allowed hosts and adds the ranges.
func (c *Controller) allowLocked(ctx context.Context, n policy.NetworkControl) allowed {
	hostList, ranges := n.Allowed()
	hosts, patterns := addrbook.ExactHosts(hostList)
	c.book.Refresh(ctx, hosts)
	out := slices.Clone(ranges)
	for a := range c.book.Addrs(hosts) {
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if d := a.Addr().Compare(b.Addr()); d != 0 {
			return d
		}
		return a.Bits() - b.Bits()
	})
	out = slices.Compact(out)
	return allowed{ranges: out, status: AllowStatus{Addresses: len(out), Unresolved: c.book.Unresolved(hosts), Patterns: patterns}}
}

func sameRules(a, b Rules) bool {
	return slices.Equal(a.BlockApps, b.BlockApps) && slices.Equal(a.Allow, b.Allow)
}

// configured reports whether cp turns the network controls on at all (for
// any OS): the module and the block are on.
func configured(cp *policy.Compiled) bool {
	return cp != nil && cp.Modules.Files.Enabled && cp.Modules.Files.DecodeError == "" && cp.Modules.Files.NetworkControl.Enabled
}

// Capabilities reports each control's capability; nil when the module or
// the block is off.
func (c *Controller) Capabilities() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !configured(c.compiled) {
		return nil
	}
	caps := map[string]string{}
	switch {
	case !c.Supported():
		caps[CapBlockedApps] = "unsupported:not_on_windows"
	case c.openErr != "":
		caps[CapBlockedApps] = "unsupported:" + c.openErr
	default:
		caps[CapBlockedApps] = "supported"
	}
	if c.Supported() {
		caps[CapTaintBlock] = "unsupported:not_implemented"
	} else {
		caps[CapTaintBlock] = "unsupported:not_on_windows"
	}
	return caps
}

// Status is the network control status; nil when the module or the block
// is off.
func (c *Controller) Status() *Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !configured(c.compiled) {
		return nil
	}
	st := c.st
	if !c.Supported() {
		st = Status{State: "unsupported:not_on_windows"}
	}
	return &st
}
