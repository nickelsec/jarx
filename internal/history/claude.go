package history

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
)

// Result is what the history readers found.
type Result struct {
	Sessions []model.Session
	Findings []finding.Finding
	Files    int // history files looked at
	Read     int // new lines read this scan
}

// Claude reads Claude Code's history under dir (~/.claude, or
// CLAUDE_CONFIG_DIR). Where the files are comes from the docs
// (code.claude.com/docs/en/sessions, "Where transcripts are stored", and
// /en/claude-directory, "Application data"): transcripts at
// projects/<project>/<session-id>.jsonl, set-aside copies of a session next
// to them (<session>.orphaned-<ts>-<suffix>.jsonl and
// <session>.jsonl.superseded-<ts>), and history.jsonl, the prompts you
// typed. The <project> name is the cwd with every non-alphanumeric turned
// into a dash, so it can't be turned back into a path: the real cwd comes
// from the records.
//
// What's inside is observed, not documented (the docs call the format
// internal; boughs docs/format-claude-code.md has our notes): one JSON
// record per line, with sessionId, cwd and timestamp on most records, and
// permissionMode on "permission-mode" records and on prompts. Records
// replay when a session is resumed, so results merge by session id. Only
// top-level files count: a session's own dir holds subagent transcripts and
// tool output, which aren't sessions.
func Claude(c agent.Context, cur *Cursor, dir string) Result {
	r := reader{c: c, cur: cur}
	projects := filepath.Join(dir, "projects")
	folders, _ := c.Files.ReadDir(projects)
	for _, folder := range folders {
		if !folder.IsDir() {
			continue
		}
		entries, _ := c.Files.ReadDir(filepath.Join(projects, folder.Name()))
		for _, e := range entries {
			if e.Type().IsRegular() && strings.Contains(e.Name(), ".jsonl") {
				r.transcript(filepath.Join(projects, folder.Name(), e.Name()))
			}
		}
	}
	if info, err := c.Files.Stat(filepath.Join(dir, "history.jsonl")); err == nil && info.Mode().IsRegular() {
		r.leaksOnly(filepath.Join(dir, "history.jsonl"))
	}
	return r.result(model.AgentClaude)
}

type reader struct {
	c     agent.Context
	cur   *Cursor
	files []string // in the order read
	res   Result
}

func (r *reader) transcript(path string) {
	st := r.cur.state(path)
	stem, _, _ := strings.Cut(filepath.Base(path), ".") // <session-id>.jsonl, per the docs
	r.read(path, st, func(line []byte, n int) {
		r.leaks(st, line, n)
		claudeRecord(st, line, stem)
	})
}

func (r *reader) leaksOnly(path string) {
	st := r.cur.state(path)
	r.read(path, st, func(line []byte, n int) { r.leaks(st, line, n) })
}

func (r *reader) read(path string, st *fileState, fn func(line []byte, n int)) {
	r.files = append(r.files, path)
	r.res.Files++
	got := readNew(r.c, st, path, fn)
	r.res.Read += got.lines
	if got.tooLarge {
		*st = fileState{} // nothing kept from a file jarx no longer reads
		t, _ := r.c.Scrub.Scrub("over 200 MB, so it wasn't read")
		r.res.Findings = append(r.res.Findings, TooLarge().New(r.origin(path, 0), t))
	}
}

// leaks records each secret on the line by type and fingerprint. A likely
// placeholder isn't a leak.
func (r *reader) leaks(st *fileState, line []byte, n int) {
	_, found := r.c.Scrub.Scrub(string(line))
	for _, f := range found {
		l := leak{Kind: f.Kind, Fingerprint: f.Fingerprint, Line: n}
		if !f.LikelyPlaceholder && !slices.Contains(st.Leaks, l) {
			st.Leaks = append(st.Leaks, l)
		}
	}
}

// modeRe and idRe are what a mode and a session id look like. Anything
// else in those fields isn't kept, so the cursor can't pick up content.
var (
	modeRe = regexp.MustCompile(`^[A-Za-z]{1,32}$`)
	idRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
)

// claudeRecord folds one transcript record into its session. Fields that
// are missing or not strings are skipped.
func claudeRecord(st *fileState, line []byte, stem string) {
	var rec map[string]json.RawMessage
	if json.Unmarshal(line, &rec) != nil {
		return
	}
	s := st.session(str(rec["sessionId"]), stem)
	if cwd := str(rec["cwd"]); cwd != "" && s.CWD == "" {
		s.CWD = upperDrive(cwd)
	}
	if mode := str(rec["permissionMode"]); modeRe.MatchString(mode) && !slices.Contains(s.Modes, mode) {
		s.Modes = append(s.Modes, mode)
	}
	if ts, err := time.Parse(time.RFC3339Nano, str(rec["timestamp"])); err == nil && ts.After(s.Last) {
		s.Last = ts.UTC()
	}
}

// session is the record's session: its own id when it looks like one, or
// the file's.
func (st *fileState) session(id, stem string) *sessionState {
	if !idRe.MatchString(id) {
		id = stem
	}
	if st.Sessions == nil {
		st.Sessions = map[string]*sessionState{}
	}
	s, ok := st.Sessions[id]
	if !ok {
		s = &sessionState{}
		st.Sessions[id] = s
	}
	return s
}

func str(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// upperDrive upper-cases a Windows drive letter, which the notes say
// varies between records of one session (d:\ and D:\).
func upperDrive(p string) string {
	if len(p) >= 2 && p[1] == ':' {
		return strings.ToUpper(p[:1]) + p[1:]
	}
	return p
}
