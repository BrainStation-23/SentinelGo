package report

import "sync"

// ownerCache resolves a file's owner to a name ("DOMAIN\user", "user"),
// remembering each uid or SID's name. Any failure is "": the owner is
// optional evidence.
type ownerCache struct {
	mu    sync.Mutex
	names map[string]string
}

func newOwnerCache() *ownerCache { return &ownerCache{names: map[string]string{}} }

func (c *ownerCache) lookup(path string) string {
	id, ok := ownerID(path)
	if !ok {
		return ""
	}
	c.mu.Lock()
	name, cached := c.names[id]
	c.mu.Unlock()
	if cached {
		return name
	}
	name = ownerName(id)
	c.mu.Lock()
	c.names[id] = name
	c.mu.Unlock()
	return name
}
