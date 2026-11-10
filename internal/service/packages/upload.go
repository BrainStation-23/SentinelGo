package packages

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"
)

// Per-call limits of agent_enqueue_packages: 5,000 packages and 1 MB of
// JSON. maxPartBytes leaves room for the envelope and the RPC wrapper.
const (
	maxPartPackages = 5000
	maxPartBytes    = 900 << 10
	// maxParts is the server's cap on parts in one snapshot.
	maxParts = 1000
)

// partTimeout bounds one upload call, retries included.
const partTimeout = 2 * time.Minute

// Snapshot kinds.
const (
	snapshotFull  = "full"
	snapshotDelta = "delta"
)

// Enqueuer sends one upload (Client.Enqueue).
type Enqueuer interface {
	Enqueue(ctx context.Context, u Upload) error
}

// splitParts groups pkgs into parts within the per-call limits.
func splitParts(pkgs []Package) [][]Package {
	var parts [][]Package
	var cur []Package
	size := 0
	for _, p := range pkgs {
		b, err := json.Marshal(p)
		if err != nil {
			continue // a Package of strings always marshals
		}
		n := len(b) + 1 // the comma
		if len(cur) > 0 && (len(cur) >= maxPartPackages || size+n > maxPartBytes) {
			parts = append(parts, cur)
			cur, size = nil, 0
		}
		cur = append(cur, p)
		size += n
	}
	if len(cur) > 0 || len(parts) == 0 {
		parts = append(parts, cur) // an empty inventory is one empty part
	}
	return parts
}

// send uploads pkgs. A complete inventory goes as a full snapshot, so the
// server retires packages the device no longer has once every part has
// arrived. An incomplete one goes as deltas without removals: it adds and
// refreshes what was seen and retires nothing.
func send(ctx context.Context, e Enqueuer, pkgs []Package, complete bool, now time.Time) (parts int, err error) {
	chunks := splitParts(pkgs)
	if len(chunks) > maxParts {
		chunks = chunks[:maxParts]
		complete = false
	}
	base := Upload{Snapshot: snapshotDelta, CollectedAt: now.UTC().Format(time.RFC3339)}
	if complete {
		base.Snapshot = snapshotFull
		base.SnapshotID = rand.Text()
		if len(chunks) > 1 {
			base.Parts = len(chunks)
		}
	}
	for i, chunk := range chunks {
		u := base
		u.Packages = chunk
		if u.Parts > 0 {
			u.Part = i + 1
		}
		if err := enqueuePart(ctx, e, u); err != nil {
			return i, fmt.Errorf("upload part %d of %d: %w", i+1, len(chunks), err)
		}
	}
	return len(chunks), nil
}

func enqueuePart(ctx context.Context, e Enqueuer, u Upload) error {
	ctx, cancel := context.WithTimeout(ctx, partTimeout)
	defer cancel()
	return e.Enqueue(ctx, u)
}
