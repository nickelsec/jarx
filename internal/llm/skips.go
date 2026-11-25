package llm

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/nickelsec/jarx/internal/jarxdir"
	"github.com/nickelsec/jarx/internal/platform"
)

// skipsFile is the artifacts the user chose not to send, in jarx's state
// dir: each one's KeyOf, a hash of its content, so a skip lasts until the
// artifact changes. It holds hashes and times only.
const (
	skipsFile    = "llm-skips.json"
	skipsVersion = 1
)

// Skips is the artifacts the user chose not to send.
type Skips struct {
	mu   sync.Mutex
	keys map[string]int64 // KeyOf to when it was skipped, Unix seconds
}

type skipsJSON struct {
	Version int              `json:"version"`
	Keys    map[string]int64 `json:"keys"`
}

// LoadSkips reads the skip list without creating the state dir. Nothing
// saved, a broken file or one from a newer jarx skips nothing.
func LoadSkips(env platform.Env) *Skips {
	s := &Skips{keys: map[string]int64{}}
	data, err := jarxdir.ReadState(env, skipsFile)
	if err != nil {
		return s
	}
	var f skipsJSON
	if json.Unmarshal(data, &f) != nil || f.Version != skipsVersion || f.Keys == nil {
		return s
	}
	s.keys = f.Keys
	return s
}

// Has says whether the artifact with this key is skipped.
func (s *Skips) Has(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.keys[key]
	return ok
}

// Len is how many artifacts are skipped.
func (s *Skips) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.keys)
}

// Set skips the artifacts with these keys, or unskips them.
func (s *Skips) Set(keys []string, skip bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	for _, k := range keys {
		if skip {
			s.keys[k] = now
		} else {
			delete(s.keys, k)
		}
	}
}

// Save writes the skip list.
func (s *Skips) Save(env platform.Env) error {
	s.mu.Lock()
	data, err := json.Marshal(skipsJSON{Version: skipsVersion, Keys: s.keys})
	s.mu.Unlock()
	if err != nil {
		return fmt.Errorf("encoding the skip list: %w", err)
	}
	d, err := jarxdir.Open(env)
	if err != nil {
		return fmt.Errorf("saving the skip list: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.WriteFile(skipsFile, data); err != nil {
		return fmt.Errorf("saving the skip list: %w", err)
	}
	return nil
}

// Unskipped is arts without the skipped ones, and how many were skipped.
func Unskipped(arts []Artifact, s *Skips) ([]Artifact, int) {
	out := make([]Artifact, 0, len(arts))
	for _, a := range arts {
		if !s.Has(KeyOf(a)) {
			out = append(out, a)
		}
	}
	return out, len(arts) - len(out)
}
