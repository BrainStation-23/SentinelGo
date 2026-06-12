package native

import (
	"context"
	"slices"

	"sentinelgo/internal/config"
	"sentinelgo/internal/taskstore"
)

// Handler is the interface every native task handler must implement.
// Slugs returns the task slug strings this handler claims.
// Run executes the task and returns a human-readable note and any error.
type Handler interface {
	Slugs() []string
	Run(ctx context.Context, cfg *config.Config, task taskstore.Task) (string, error)
}

// PostRunner is an optional interface a Handler may implement to declare slugs
// that should run automatically after the handler completes successfully.
// Post-run failures are logged but do not affect the primary task's status.
type PostRunner interface {
	PostRun() []string
}

var registry []Handler

// Register adds h to the global registry. Call from init() in each handler file.
// All Register calls come from init() functions, which run sequentially before
// any goroutine can access the registry, so no mutex is needed.
func Register(h Handler) {
	registry = append(registry, h)
}

// Registry returns a snapshot of all registered handlers.
func Registry() []Handler {
	out := make([]Handler, len(registry))
	copy(out, registry)
	return out
}

// Find returns the first registered handler that claims slug, or nil.
func Find(slug string) Handler {
	for _, h := range registry {
		if slices.Contains(h.Slugs(), slug) {
			return h
		}
	}
	return nil
}
