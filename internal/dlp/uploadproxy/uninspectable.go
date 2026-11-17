package uploadproxy

import (
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"sentinelgo/internal/sanitize"
)

// Why an upload to an intercepted host couldn't be inspected (#527). They
// are reported in files.deep_inspection, so admins can tell "inspected and
// clean" from "never inspected".
const (
	// ReasonTLSUntrusted: the client got the proxy's certificate for the host
	// and then refused it or dropped the connection. A pinned app, or a
	// client that doesn't trust the device CA (its own trust store, an
	// enterprise policy that isn't applied).
	ReasonTLSUntrusted = "tls_untrusted"
	// ReasonWebSocket: a WebSocket upgrade. The proxy relays the stream but
	// doesn't read what is sent through it.
	ReasonWebSocket = "websocket"
	// ReasonTooLarge: a body over the files module's max_file_bytes. It is
	// decided by on_unscannable (and recorded as unscannable:too_large by
	// the file policies); counted here too so the coverage numbers are whole.
	ReasonTooLarge = "too_large"
)

// maxUninspectableHosts caps the per-host list in the status report. When it
// is full the entry seen longest ago makes room.
const maxUninspectableHosts = 20

// maxHostLen is the longest host name kept (a DNS name is at most 253).
const maxHostLen = 253

// UninspectableHost is one host and reason in the status report: how often
// it happened and when. It holds the host only, never a URL, a path or
// anything the client sent.
type UninspectableHost struct {
	Host    string    `json:"host"`
	Reason  string    `json:"reason"`
	Count   uint64    `json:"count"`
	FirstAt time.Time `json:"first_at"`
	LastAt  time.Time `json:"last_at"`
}

type hostReason struct{ host, reason string }

// uninspectable counts uploads the proxy couldn't inspect, by reason and by
// host. Repeats of the same host and reason fold into one entry: a pinned
// client retries constantly, and only the first is logged.
type uninspectable struct {
	mu     sync.Mutex
	now    func() time.Time
	counts map[string]uint64
	hosts  map[hostReason]*UninspectableHost
}

func newUninspectable(now func() time.Time) *uninspectable {
	if now == nil {
		now = time.Now
	}
	return &uninspectable{now: now, counts: map[string]uint64{}, hosts: map[hostReason]*UninspectableHost{}}
}

// add records one upload to host that couldn't be inspected for reason.
func (u *uninspectable) add(host, reason string) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if len(host) > maxHostLen {
		host = host[:maxHostLen]
	}
	now := u.now().UTC()
	u.mu.Lock()
	defer u.mu.Unlock()
	u.counts[reason]++
	k := hostReason{host, reason}
	if e, ok := u.hosts[k]; ok {
		e.Count++
		e.LastAt = now
		return
	}
	if len(u.hosts) >= maxUninspectableHosts {
		var oldest hostReason
		var at time.Time
		for hk, e := range u.hosts {
			if at.IsZero() || e.LastAt.Before(at) {
				oldest, at = hk, e.LastAt
			}
		}
		delete(u.hosts, oldest)
	}
	u.hosts[k] = &UninspectableHost{Host: host, Reason: reason, Count: 1, FirstAt: now, LastAt: now}
	log.Printf("DLP: an upload to %s couldn't be inspected (%s)", sanitize.ForLog(host), reason) // #nosec G706 -- the client-supplied host has its line breaks removed (sanitize.ForLog)
}

// snapshot returns the counts by reason and the hosts, most recent first;
// nil for both when nothing was recorded.
func (u *uninspectable) snapshot() (map[string]uint64, []UninspectableHost) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.counts) == 0 {
		return nil, nil
	}
	counts := make(map[string]uint64, len(u.counts))
	for r, n := range u.counts {
		counts[r] = n
	}
	hosts := make([]UninspectableHost, 0, len(u.hosts))
	for _, e := range u.hosts {
		hosts = append(hosts, *e)
	}
	sort.Slice(hosts, func(i, j int) bool {
		if !hosts[i].LastAt.Equal(hosts[j].LastAt) {
			return hosts[i].LastAt.After(hosts[j].LastAt)
		}
		if hosts[i].Host != hosts[j].Host {
			return hosts[i].Host < hosts[j].Host
		}
		return hosts[i].Reason < hosts[j].Reason
	})
	return counts, hosts
}
