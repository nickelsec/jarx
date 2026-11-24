package history

import (
	"encoding/json"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/model"
)

// Codex reads Codex's history. What's documented
// (developers.openai.com/codex/config-advanced and config-reference): state
// lives under CODEX_HOME, history.jsonl holds session transcripts unless
// history.persistence is "none", and sqlite_home is the dir of the SQLite
// state DB (its default isn't given; jarx uses CODEX_HOME, where it's
// observed).
//
// The rest is observed, not documented (boughs docs/format-codex.md has our
// notes): rollouts at sessions/YYYY/MM/DD/rollout-<ts>-<id>.jsonl, older
// ones compressed as .jsonl.zst, one {timestamp, ordinal, type, payload}
// record per line. session_meta names the session (session_id, else id)
// and its cwd; turn_context has approval_policy, approvals_reviewer and
// sandbox_policy.type. Codex replays a resumed session into a new rollout,
// and a sub-agent's rollout carries its parent's session_id, so results
// merge by session. state_N.sqlite has a threads table with each thread's
// cwd and modes, and memories_N.sqlite has the raw memories Codex wrote.
func Codex(c agent.Context, cur *Cursor, home, sqliteHome string) Result {
	r := reader{c: c, cur: cur, agent: model.AgentCodex, dbs: map[string]*fileState{}}
	var rollouts []string
	_ = c.Files.Walk(filepath.Join(home, "sessions"), func(path string, d fs.DirEntry) error {
		name := filepath.Base(path)
		if d.Type().IsRegular() && strings.HasPrefix(name, "rollout-") && (strings.HasSuffix(name, ".jsonl") || strings.HasSuffix(name, ".jsonl.zst")) {
			rollouts = append(rollouts, path)
		}
		return nil
	})
	for _, path := range rollouts {
		r.rollout(path)
	}
	if info, err := c.Files.Stat(filepath.Join(home, "history.jsonl")); err == nil && info.Mode().IsRegular() {
		r.leaksOnly(filepath.Join(home, "history.jsonl"))
	}
	r.databases(sqliteHome)
	return r.result()
}

func (r *reader) rollout(path string) {
	st := r.cur.state(path)
	fallback := rolloutID(filepath.Base(path))
	fn := func(line []byte, n int) {
		r.leaks(st, line, n)
		codexRecord(st, line, fallback)
	}
	if strings.HasSuffix(path, ".zst") {
		r.readCompressed(path, st, fn)
		return
	}
	r.read(path, st, fn)
}

// rolloutID is the id at the end of rollout-<ts>-<id>.jsonl, for a file
// with no session_meta.
func rolloutID(name string) string {
	name = strings.TrimSuffix(strings.TrimSuffix(name, ".zst"), ".jsonl")
	if i := strings.LastIndex(name, "-"); i >= 0 && len(name)-i-1 >= 36 {
		return name[len(name)-36:]
	}
	return name
}

// modeValueRe is what a mode's value looks like, like on-request or
// danger-full-access. Anything else isn't kept.
var modeValueRe = regexp.MustCompile(`^[A-Za-z][A-Za-z_-]{0,31}$`)

func codexRecord(st *fileState, line []byte, fallback string) {
	var rec struct {
		Type      string                     `json:"type"`
		Timestamp string                     `json:"timestamp"`
		Payload   map[string]json.RawMessage `json:"payload"`
	}
	if json.Unmarshal(line, &rec) != nil || rec.Payload == nil {
		return
	}
	if rec.Type == "session_meta" {
		st.Session = metaSession(rec.Payload)
	}
	s := st.session(st.Session, fallback)
	if cwd := str(rec.Payload["cwd"]); cwd != "" && s.CWD == "" {
		s.CWD = upperDrive(cwd)
	}
	if rec.Type == "turn_context" {
		s.addModes(turnModes(rec.Payload))
	}
	if ts, err := time.Parse(time.RFC3339Nano, rec.Timestamp); err == nil && ts.After(s.Last) {
		s.Last = ts.UTC()
	}
}

// addModes adds each mode the session doesn't have yet.
func (s *sessionState) addModes(modes []string) {
	for _, m := range modes {
		if !slices.Contains(s.Modes, m) {
			s.Modes = append(s.Modes, m)
		}
	}
}

// metaSession is the session a rollout belongs to: session_id, which a
// sub-agent shares with its parent, else id.
func metaSession(p map[string]json.RawMessage) string {
	for _, key := range []string{"session_id", "id"} {
		if id := str(p[key]); idRe.MatchString(id) {
			return id
		}
	}
	return ""
}

// turnModes are a turn's approval policy, reviewer and sandbox. A granular
// policy is named, not spelled out: its flags say which prompts are
// auto-rejected (config-reference, approval_policy.granular).
func turnModes(p map[string]json.RawMessage) []string {
	var out []string
	add := func(key, v string) {
		if modeValueRe.MatchString(v) {
			out = append(out, key+"="+v)
		}
	}
	if policy := str(p["approval_policy"]); policy != "" {
		add("approval_policy", policy)
	} else {
		var obj map[string]json.RawMessage
		if json.Unmarshal(p["approval_policy"], &obj) == nil && obj["granular"] != nil {
			add("approval_policy", "granular")
		}
	}
	add("approvals_reviewer", str(p["approvals_reviewer"]))
	add("sandbox", sandboxType(p["sandbox_policy"]))
	return out
}

func sandboxType(raw json.RawMessage) string {
	var sb struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &sb) != nil {
		return str(raw) // older rollouts may write it as a plain string
	}
	return sb.Type
}
