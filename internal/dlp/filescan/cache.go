package filescan

import (
	"container/list"
	"sync"
)

// CacheKey identifies one version of one file under one policy. FileID is the
// OS file identity (Windows: volume serial + 128-bit file id; macOS/Linux:
// device + inode). Size and both times make an edited file a new key, and
// PolicyVersion makes a new policy rescan everything instead of reusing old
// verdicts.
type CacheKey struct {
	FileID        string
	Size          int64
	ModTime       int64 // Unix nanoseconds
	ChangeTime    int64 // Unix nanoseconds (ctime; Windows: change time)
	PolicyVersion string
}

// Cache is a bounded LRU of scan results. It is safe for concurrent use.
type Cache struct {
	mu     sync.Mutex
	max    int
	ll     *list.List // front = most recently used
	items  map[CacheKey]*list.Element
	byFile map[string]map[CacheKey]struct{}
}

type cacheEntry struct {
	key CacheKey
	res Result
}

// NewCache returns a cache holding at most max results.
func NewCache(max int) *Cache {
	return &Cache{max: max, ll: list.New(), items: map[CacheKey]*list.Element{}, byFile: map[string]map[CacheKey]struct{}{}}
}

// Get returns the cached result for k. The result shares its slices with the
// cache: treat it as read-only.
func (c *Cache) Get(k CacheKey) (Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[k]
	if !ok {
		return Result{}, false
	}
	c.ll.MoveToFront(el)
	return el.Value.(*cacheEntry).res, true
}

// Put stores r for k. A timeout isn't stored: the next try may finish.
func (c *Cache) Put(k CacheKey, r Result) {
	if r.Status == StatusTimeout || c.max <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[k]; ok {
		el.Value.(*cacheEntry).res = r
		c.ll.MoveToFront(el)
		return
	}
	c.items[k] = c.ll.PushFront(&cacheEntry{key: k, res: r})
	if c.byFile[k.FileID] == nil {
		c.byFile[k.FileID] = map[CacheKey]struct{}{}
	}
	c.byFile[k.FileID][k] = struct{}{}
	for c.ll.Len() > c.max {
		c.removeLocked(c.ll.Back())
	}
}

// InvalidateFile drops every result for a file, e.g. when the OS hook reports
// it was closed after a write (its times may not have changed yet, and an
// mmap write changes nothing we key on).
func (c *Cache) InvalidateFile(fileID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.byFile[fileID] {
		c.removeLocked(c.items[k])
	}
}

// Clear drops everything.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll.Init()
	c.items = map[CacheKey]*list.Element{}
	c.byFile = map[string]map[CacheKey]struct{}{}
}

// Len is the number of cached results.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

func (c *Cache) removeLocked(el *list.Element) {
	e := el.Value.(*cacheEntry)
	c.ll.Remove(el)
	delete(c.items, e.key)
	if m := c.byFile[e.key.FileID]; m != nil {
		delete(m, e.key)
		if len(m) == 0 {
			delete(c.byFile, e.key.FileID)
		}
	}
}
