package software

import (
	"log"
)

// HashFunc is the signature for a file-hashing function. Using a function type
// (rather than importing internal/hashutil directly) keeps this file fully
// testable without touching the filesystem — tests inject a mock.
type HashFunc func(path string) (string, error)

// EnrichWithHash populates SHA256Hash on each SoftwareInfo that has a non-empty
// FilePath and whose hash is not already present in cache. Items with no
// FilePath (package-manager entries without a resolved binary, browser
// extensions, etc.) are left unchanged.
//
// cache maps the composite key "<name>\x00<source>" → previously-stored
// sha256_hash. A non-empty cache hit means the binary was hashed in a prior
// cycle; the cached value is reused and computeHash is not called. This avoids
// re-reading every installed binary on every sync cycle.
//
// computeHash errors are logged at warning level and never propagate: a single
// unreadable file (SIP-protected path, race with uninstaller, etc.) must not
// abort the rest of the enrichment pass or block the sync upload.
//
// The slice is modified in-place and returned for convenient chaining.
func EnrichWithHash(items []SoftwareInfo, cache map[string]string, computeHash HashFunc) []SoftwareInfo {
	for i := range items {
		if items[i].FilePath == "" {
			// No binary path — nothing to hash (package-manager entry,
			// extension, or Store app without an InstallLocation).
			continue
		}

		key := items[i].Name + "\x00" + items[i].Source

		if cached, ok := cache[key]; ok && cached != "" {
			// Hash already computed in a previous cycle; reuse it.
			items[i].SHA256Hash = cached
			continue
		}

		hash, err := computeHash(items[i].FilePath)
		if err != nil {
			// Non-fatal: permission denied, SIP, file removed between scan and
			// hash — leave SHA256Hash empty rather than failing the whole sync.
			log.Printf("[software] enrich: hash skipped for %q (%s): %v",
				items[i].Name, items[i].FilePath, err)
			continue
		}

		items[i].SHA256Hash = hash
	}

	return items
}
