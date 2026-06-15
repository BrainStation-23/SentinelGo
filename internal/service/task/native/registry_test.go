package native_test

import (
	"context"
	"testing"

	"sentinelgo/internal/config"
	"sentinelgo/internal/service/task/native"
	"sentinelgo/internal/taskstore"
)

func TestRegistry_NotEmpty(t *testing.T) {
	handlers := native.Registry()
	if len(handlers) == 0 {
		t.Fatal("Registry() returned no handlers; expected at least one registered handler")
	}
}

func TestRegistry_ContainsAllExpectedSlugs(t *testing.T) {
	expectedSlugs := []string{
		"agent-update",
		"firewall-disable",
		"firewall-enable",
		"reboot-device",
		"sync-inventory",
		"sync-software",
	}
	for _, slug := range expectedSlugs {
		h := native.Find(slug)
		if h == nil {
			t.Errorf("Find(%q) returned nil; handler should be registered", slug)
		}
	}
}

func TestFind_ReturnsNilForUnknownSlug(t *testing.T) {
	h := native.Find("no-such-slug-xyz-999")
	if h != nil {
		t.Errorf("Find(unknown slug) returned non-nil: %v", h)
	}
}

func TestRegistry_SlugUniqueness(t *testing.T) {
	seen := make(map[string]string) // slug → handler type
	for _, h := range native.Registry() {
		for _, slug := range h.Slugs() {
			if prev, exists := seen[slug]; exists {
				t.Errorf("slug %q is registered by multiple handlers: %T and %s", slug, h, prev)
			}
			seen[slug] = ""
		}
	}
}

func TestRegistry_ReturnsCopy(t *testing.T) {
	r1 := native.Registry()
	if len(r1) == 0 {
		t.Skip("registry is empty, nothing to test")
	}
	original := r1[0]
	r1[0] = nil

	r2 := native.Registry()
	if r2[0] == nil {
		t.Error("Registry() returned a shared underlying slice; mutation of one result affected another")
	}
	if r2[0] != original {
		t.Error("Registry() returned unexpected first element after mutation test")
	}
}

func TestFind_ReturnsCorrectHandler(t *testing.T) {
	slugs := []string{"agent-update", "firewall-disable", "firewall-enable", "reboot-device", "sync-inventory", "sync-software"}
	for _, slug := range slugs {
		h := native.Find(slug)
		if h == nil {
			t.Errorf("Find(%q) returned nil", slug)
			continue
		}
		found := false
		for _, s := range h.Slugs() {
			if s == slug {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Find(%q) returned a handler whose Slugs() does not contain %q: %v", slug, slug, h.Slugs())
		}
	}
}

func TestRegistry_AllHandlersImplementInterface(t *testing.T) {
	for _, h := range native.Registry() {
		if len(h.Slugs()) == 0 {
			t.Errorf("handler %T returned empty Slugs()", h)
		}
	}
}

func TestPostRunnerHandlers_HaveValidPostSlugs(t *testing.T) {
	for _, h := range native.Registry() {
		pr, ok := h.(native.PostRunner)
		if !ok {
			continue
		}
		for _, postSlug := range pr.PostRun() {
			ph := native.Find(postSlug)
			if ph == nil {
				t.Errorf("handler %T declares post-run slug %q but no handler is registered for it", h, postSlug)
			}
		}
	}
}

// Verify that native.Handler and native.PostRunner are the interfaces the
// package expects — compile-time guard using a local test-only implementation.
type noopHandler struct{}

func (noopHandler) Slugs() []string { return []string{"noop"} }
func (noopHandler) Run(_ context.Context, _ *config.Config, _ taskstore.Task) (string, error) {
	return "", nil
}

var _ native.Handler = noopHandler{}
