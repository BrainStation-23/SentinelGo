package walk

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"sentinelgo/internal/winsec"
)

// Result is what the last scan of a file found.
type Result uint8

// Results the skip cache keeps. Files that failed to scan aren't cached.
const (
	Clean   Result = 1
	Matched Result = 2
)

// Key identifies a file's content as far as the file system can tell
// without reading it: its path, size, modification time and change time
// (ctime on Unix, where any write or rename updates it; creation time on
// Windows).
type Key struct {
	Path   string
	Size   int64
	MTime  int64 // Unix nanoseconds
	Change int64 // Unix nanoseconds
}

// DefaultCacheEntries bounds the cache file (37 bytes an entry, so 37 MB).
const DefaultCacheEntries = 1_000_000

// cacheMagic starts the file; the byte after it is the format version.
var cacheMagic = []byte("SGYC")

const (
	cacheVersion   = 1
	cacheRecordLen = 16 + 16 + 1 + 4
)

// Cache is the on-disk skip cache (#413): for each file scanned, a
// signature of its Key and the ruleset set, and the result. A scheduled
// scan skips a file whose signature still matches, so after the first
// scan only new and changed files (or every file, after a rules change)
// are read. Paths are stored only as hashes.
type Cache struct {
	path string
	fold bool // compare paths case-insensitively (Windows)
	max  int

	mu      sync.Mutex
	gen     uint32
	entries map[[16]byte]cacheEntry
	dirty   bool
}

type cacheEntry struct {
	sig    [16]byte
	result Result
	seen   uint32 // scan generation that last saw the file
}

// OpenCache loads the cache at path. A missing file is an empty cache; a
// file this agent can't read (corrupt, another version) is an empty cache
// plus an error for the log, and is replaced on the next Save.
func OpenCache(path, goos string) (*Cache, error) {
	c := &Cache{path: path, fold: goos == "windows", max: DefaultCacheEntries, entries: map[[16]byte]cacheEntry{}}
	f, err := os.Open(path) // #nosec G304 -- the agent's own data file
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, fmt.Errorf("open YARA skip cache: %w", err)
	}
	defer func() { _ = f.Close() }()
	if err := c.read(bufio.NewReader(f)); err != nil {
		c.gen, c.entries = 0, map[[16]byte]cacheEntry{}
		return c, fmt.Errorf("YARA skip cache %s unreadable, starting empty: %w", path, err)
	}
	return c, nil
}

func (c *Cache) read(r io.Reader) error {
	var head [4 + 1 + 4 + 4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return err
	}
	if !bytes.Equal(head[:4], cacheMagic) || head[4] != cacheVersion {
		return errors.New("not a version 1 skip cache")
	}
	c.gen = binary.LittleEndian.Uint32(head[5:9])
	n := binary.LittleEndian.Uint32(head[9:13])
	if int64(n) > int64(c.max)*2 {
		return fmt.Errorf("%d entries", n)
	}
	var rec [cacheRecordLen]byte
	for range n {
		if _, err := io.ReadFull(r, rec[:]); err != nil {
			return err
		}
		var k [16]byte
		var e cacheEntry
		copy(k[:], rec[:16])
		copy(e.sig[:], rec[16:32])
		e.result = Result(rec[32])
		e.seen = binary.LittleEndian.Uint32(rec[33:])
		c.entries[k] = e
	}
	return nil
}

// SetMaxEntries changes the bound (tests).
func (c *Cache) SetMaxEntries(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.max = n
}

// BeginScan starts a scan generation; entries that later scans don't see
// are the first dropped when the cache is full.
func (c *Cache) BeginScan() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	c.dirty = true
}

// Lookup returns the cached result for k under rules (a hash of the
// ruleset set: id and revision of each), when the file hasn't changed.
func (c *Cache) Lookup(k Key, rules string) (Result, bool) {
	pk, sig := c.keys(k, rules)
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[pk]
	if !ok || e.sig != sig {
		return 0, false
	}
	if e.seen != c.gen {
		e.seen = c.gen
		c.entries[pk] = e
		c.dirty = true
	}
	return e.result, true
}

// Store records the result of scanning k under rules.
func (c *Cache) Store(k Key, rules string, r Result) {
	pk, sig := c.keys(k, rules)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[pk] = cacheEntry{sig: sig, result: r, seen: c.gen}
	c.dirty = true
}

// Len returns the number of entries.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *Cache) keys(k Key, rules string) (pk, sig [16]byte) {
	p := k.Path
	if c.fold {
		p = strings.ToLower(p)
	}
	ph := sha256.Sum256([]byte(p))
	copy(pk[:], ph[:16])
	var buf [24]byte
	binary.LittleEndian.PutUint64(buf[0:], uint64(k.Size))    // #nosec G115 -- hashed bits, sign is irrelevant
	binary.LittleEndian.PutUint64(buf[8:], uint64(k.MTime))   // #nosec G115 -- hashed bits
	binary.LittleEndian.PutUint64(buf[16:], uint64(k.Change)) // #nosec G115 -- hashed bits
	h := sha256.New()
	h.Write(buf[:])
	h.Write([]byte(rules))
	copy(sig[:], h.Sum(nil))
	return pk, sig
}

// Save writes the cache atomically, owner-only (0600 in a 0700 folder on
// Unix; SYSTEM and Administrators on Windows). Over the bound, the entries
// seen longest ago are dropped first.
func (c *Cache) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.dirty {
		return nil
	}
	c.trim()
	var buf bytes.Buffer
	buf.Grow(13 + len(c.entries)*cacheRecordLen)
	buf.Write(cacheMagic)
	buf.WriteByte(cacheVersion)
	_ = binary.Write(&buf, binary.LittleEndian, c.gen)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(len(c.entries))) // #nosec G115 -- trimmed to max
	for k, e := range c.entries {
		buf.Write(k[:])
		buf.Write(e.sig[:])
		buf.WriteByte(byte(e.result))
		_ = binary.Write(&buf, binary.LittleEndian, e.seen)
	}
	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create YARA cache folder: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "yara_skip-*.tmp")
	if err != nil {
		return fmt.Errorf("create YARA skip cache: %w", err)
	}
	tmpPath := tmp.Name()
	err = tmp.Chmod(0o600) // Windows: only the read-only bit; winsec sets the ACL below
	if err == nil {
		_, err = tmp.Write(buf.Bytes())
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmpPath, c.path)
	}
	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write YARA skip cache: %w", err)
	}
	if err := winsec.SecurePath(c.path); err != nil {
		return fmt.Errorf("restrict YARA skip cache: %w", err)
	}
	c.dirty = false
	return nil
}

// trim drops the least recently seen entries over the bound.
func (c *Cache) trim() {
	over := len(c.entries) - c.max
	if over <= 0 {
		return
	}
	type aged struct {
		k    [16]byte
		seen uint32
	}
	all := make([]aged, 0, len(c.entries))
	for k, e := range c.entries {
		all = append(all, aged{k, e.seen})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].seen != all[j].seen {
			return all[i].seen < all[j].seen
		}
		return bytes.Compare(all[i].k[:], all[j].k[:]) < 0
	})
	for _, a := range all[:over] {
		delete(c.entries, a.k)
	}
}
