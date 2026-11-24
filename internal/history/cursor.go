// Package history reads the agents' session history: Claude transcripts
// now, Codex rollouts and sqlite later. These formats are observed, not
// documented, so every reader skips what it doesn't recognize and never
// errors. It records which modes each session ran in, its real working
// dir, and which secrets ended up in it (as type and fingerprint only).
//
// Scans are incremental: the cursor remembers how far each file was read
// and what was found in it, so a scan reads only new lines and still gives
// the whole answer. The cursor holds no content.
package history

import (
	"encoding/json"
	"time"

	"github.com/nickelsec/jarx/internal/jarxdir"
	"github.com/nickelsec/jarx/internal/platform"
)

// cursorFile is the cursor's name in jarx's state dir.
const cursorFile = "history-cursor.json"

// cursorVersion changes when the cursor's shape does. A cursor of another
// version is dropped and every file is read again.
const cursorVersion = 1

// headSize is how much of a file's start the cursor hashes, to tell a file
// that was appended to from one that was rewritten.
const headSize = 4096

// Cursor is what jarx remembers between scans, per history file.
type Cursor struct {
	Version int                   `json:"version"`
	Files   map[string]*fileState `json:"files"`

	seen   map[string]bool // files that still exist, this scan
	loaded bool            // a cursor was on disk, so it may need pruning
}

// fileState is one file's read position and what was found before it. It
// keeps only ids, modes, paths, times, secret types and fingerprints.
type fileState struct {
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mtime"`
	Offset  int64     `json:"offset"` // just past the last full line read
	Lines   int       `json:"lines"`  // full lines read so far
	HeadLen int       `json:"headLen"`
	Head    string    `json:"head"` // sha256 of the first HeadLen bytes

	Sessions map[string]*sessionState `json:"sessions,omitempty"`
	Leaks    []leak                   `json:"leaks,omitempty"`
	Session  string                   `json:"session,omitempty"` // a Codex rollout's session, from its session_meta
}

type sessionState struct {
	CWD   string    `json:"cwd,omitempty"`
	Modes []string  `json:"modes,omitempty"`
	Last  time.Time `json:"last,omitzero"`
}

type leak struct {
	Kind        string `json:"kind"`
	Fingerprint string `json:"fingerprint"`
	Line        int    `json:"line"`
	Row         bool   `json:"row,omitempty"` // Line is a database row, not a line
}

// Load reads the cursor, without creating the state dir. A missing, broken
// or other-version cursor means starting over: it's jarx's own cache, so
// that's never an error.
func Load(env platform.Env) Cursor {
	empty := Cursor{Version: cursorVersion, Files: map[string]*fileState{}}
	data, err := jarxdir.ReadState(env, cursorFile)
	if err != nil {
		return empty
	}
	var c Cursor
	if json.Unmarshal(data, &c) != nil || c.Version != cursorVersion || c.Files == nil {
		empty.loaded = true // a bad one gets replaced
		return empty
	}
	c.loaded = true
	return c
}

// Save writes the cursor, dropping files that are gone, so their results
// go with them. With no history now and no cursor before, it writes
// nothing, not even the state dir.
func (c *Cursor) Save(env platform.Env) error {
	for path := range c.Files {
		if !c.seen[path] {
			delete(c.Files, path)
		}
	}
	if len(c.Files) == 0 && !c.loaded {
		return nil
	}
	c.Version = cursorVersion
	data, err := json.Marshal(c)
	if err != nil {
		return err //nolint:wrapcheck // can't fail for these types
	}
	d, err := jarxdir.Open(env)
	if err != nil {
		return err //nolint:wrapcheck // jarxdir names the dir
	}
	defer func() { _ = d.Close() }()
	return d.WriteFile(cursorFile, data) //nolint:wrapcheck // jarxdir names the file
}

// state is path's entry, marked as still there.
func (c *Cursor) state(path string) *fileState {
	if c.Files == nil {
		c.Files = map[string]*fileState{}
	}
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	c.seen[path] = true
	st, ok := c.Files[path]
	if !ok {
		st = &fileState{}
		c.Files[path] = st
	}
	return st
}
