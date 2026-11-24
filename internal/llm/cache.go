package llm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/nickelsec/jarx/internal/jarxdir"
	"github.com/nickelsec/jarx/internal/platform"
)

// cacheFile is the LLM cache in jarx's state dir: content hash to the
// findings the model gave, already quote-checked and masked. Failures are
// never kept, so they're sent again next time.
const (
	cacheFile    = "llm-cache.json"
	cacheVersion = 1
	maxCached    = 2000 // the newest are kept
)

// Cache is the LLM cache. A nil-safe zero value isn't needed: use NewCache
// or LoadCache.
type Cache struct {
	entries map[string]cacheEntry
	changed bool
}

type cacheEntry struct {
	At       int64  `json:"at"` // Unix seconds, for keeping the newest
	Findings []Item `json:"findings"`
}

type cacheJSON struct {
	Version int                   `json:"version"`
	Entries map[string]cacheEntry `json:"entries"`
}

// NewCache returns an empty cache.
func NewCache() *Cache { return &Cache{entries: map[string]cacheEntry{}} }

// LoadCache reads the cache without creating the state dir. Nothing saved,
// a broken file or one from a newer jarx is an empty cache: it only means
// more is sent.
func LoadCache(env platform.Env) *Cache {
	data, err := jarxdir.ReadState(env, cacheFile)
	if err != nil {
		return NewCache()
	}
	var f cacheJSON
	if json.Unmarshal(data, &f) != nil || f.Version != cacheVersion || f.Entries == nil {
		return NewCache()
	}
	return &Cache{entries: f.Entries}
}

// Len is how many artifacts the cache knows.
func (c *Cache) Len() int { return len(c.entries) }

// Save writes the cache when the review added to it, keeping the newest
// maxCached entries.
func (c *Cache) Save(env platform.Env) error {
	if !c.changed {
		return nil
	}
	if len(c.entries) > maxCached {
		keys := make([]string, 0, len(c.entries))
		for k := range c.entries {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, func(a, b string) int { return int(c.entries[b].At - c.entries[a].At) })
		for _, k := range keys[maxCached:] {
			delete(c.entries, k)
		}
	}
	data, err := json.Marshal(cacheJSON{Version: cacheVersion, Entries: c.entries})
	if err != nil {
		return fmt.Errorf("encoding the llm cache: %w", err)
	}
	d, err := jarxdir.Open(env)
	if err != nil {
		return fmt.Errorf("saving the llm cache: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.WriteFile(cacheFile, data); err != nil {
		return fmt.Errorf("saving the llm cache: %w", err)
	}
	c.changed = false
	return nil
}

func (c *Cache) get(key string) ([]Item, bool) {
	e, ok := c.entries[key]
	return e.Findings, ok
}

func (c *Cache) put(key string, items []Item) {
	if items == nil {
		items = []Item{}
	}
	c.entries[key] = cacheEntry{At: time.Now().Unix(), Findings: items}
	c.changed = true
}

// cacheKey is a hash of what decides the answer: the prompt version, the
// endpoint, the model and the artifact as sent.
func cacheKey(ep Endpoint, msg string) string {
	h := sha256.New()
	for _, part := range []string{promptVersion, ep.BaseURL, ep.Model, msg} {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
