package filescan

import (
	"fmt"
	"sync"
	"testing"
)

func TestCache(t *testing.T) {
	c := NewCache(3)
	k := func(id string, v string) CacheKey {
		return CacheKey{FileID: id, Size: 10, ModTime: 1, ChangeTime: 2, PolicyVersion: v}
	}
	c.Put(k("a", "v1"), Result{Status: StatusScanned, DetectedType: "a"})
	if r, ok := c.Get(k("a", "v1")); !ok || r.DetectedType != "a" {
		t.Fatalf("get = %+v %v", r, ok)
	}
	// A new policy version, size or time is a different key.
	for _, other := range []CacheKey{k("a", "v2"), {FileID: "a", Size: 11, ModTime: 1, ChangeTime: 2, PolicyVersion: "v1"},
		{FileID: "a", Size: 10, ModTime: 1, ChangeTime: 3, PolicyVersion: "v1"}} {
		if _, ok := c.Get(other); ok {
			t.Errorf("hit for %+v", other)
		}
	}
	// Timeouts aren't cached.
	c.Put(k("t", "v1"), Result{Status: StatusTimeout})
	if _, ok := c.Get(k("t", "v1")); ok {
		t.Error("timeout cached")
	}
	// LRU: "a" was used last, so "b" goes first.
	c.Put(k("b", "v1"), Result{Status: StatusScanned})
	c.Put(k("c", "v1"), Result{Status: StatusScanned})
	c.Get(k("a", "v1"))
	c.Put(k("d", "v1"), Result{Status: StatusScanned})
	if _, ok := c.Get(k("b", "v1")); ok || c.Len() != 3 {
		t.Errorf("b not evicted (len %d)", c.Len())
	}
	if _, ok := c.Get(k("a", "v1")); !ok {
		t.Error("a evicted")
	}
	// Invalidate drops every version of a file.
	c.Put(k("a", "v2"), Result{Status: StatusScanned})
	c.InvalidateFile("a")
	if _, ok := c.Get(k("a", "v1")); ok {
		t.Error("a v1 survived invalidation")
	}
	if _, ok := c.Get(k("a", "v2")); ok {
		t.Error("a v2 survived invalidation")
	}
	c.Clear()
	if c.Len() != 0 {
		t.Errorf("len after clear %d", c.Len())
	}
	// Disabled cache.
	z := NewCache(0)
	z.Put(k("a", "v1"), Result{Status: StatusScanned})
	if z.Len() != 0 {
		t.Error("zero-size cache stored a result")
	}
}

func TestCache_Concurrent(t *testing.T) {
	c := NewCache(50)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				key := CacheKey{FileID: fmt.Sprint(i % 70), PolicyVersion: "v"}
				c.Put(key, Result{Status: StatusScanned})
				c.Get(key)
				if i%50 == 0 {
					c.InvalidateFile(fmt.Sprint(g))
				}
			}
		}(g)
	}
	wg.Wait()
	if c.Len() > 50 {
		t.Errorf("len %d over max", c.Len())
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, m := range c.byFile {
		n += len(m)
	}
	if n != len(c.items) || n != c.ll.Len() {
		t.Errorf("index out of sync: byFile %d items %d list %d", n, len(c.items), c.ll.Len())
	}
}
