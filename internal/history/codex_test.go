package history

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	_ "modernc.org/sqlite" // the test builds its fixture databases with it
)

// rollout is one Codex rollout line: {timestamp, ordinal, type, payload}.
func rollout(typ string, payload map[string]any) string {
	b, err := json.Marshal(map[string]any{"timestamp": "2026-11-22T10:00:00.000Z", "ordinal": 0, "type": typ, "payload": payload})
	if err != nil {
		panic(err)
	}
	return string(b) + "\n"
}

// meta is session t1's session_meta.
func meta(cwd string) string { return subMeta("t1", "t1", cwd) }

// subMeta is a sub-agent's session_meta: its own id, its parent's session.
func subMeta(id, parent, cwd string) string {
	return rollout("session_meta", map[string]any{"id": id, "session_id": parent, "cwd": cwd, "timestamp": "2026-11-22T10:00:00.000Z"})
}

func turn(policy any, reviewer, sandbox string) string {
	return rollout("turn_context", map[string]any{
		"approval_policy": policy, "approvals_reviewer": reviewer, "sandbox_policy": map[string]any{"type": sandbox}, "cwd": "/ignored/when/meta/has/one",
	})
}

func said(text string) string {
	return rollout("response_item", map[string]any{"type": "message", "role": "user", "content": []map[string]any{{"type": "input_text", "text": text}}})
}

func (w *world) codexScan() Result {
	w.t.Helper()
	c := w.context()
	cur := Load(c.Env)
	home := filepath.Join(c.Env.Home, ".codex")
	res := Codex(c, &cur, home, home)
	if err := cur.Save(c.Env); err != nil {
		w.t.Fatal(err)
	}
	return res
}

const day = ".codex/sessions/2026/11/22/"

func TestARolloutGivesItsSessionCwdAndModes(t *testing.T) {
	w := newWorld(t)
	w.write(day+"rollout-2026-11-22T10-00-00-t1.jsonl", meta("/w/notes")+turn("never", "user", "danger-full-access")+said("hello"))

	got := w.sessionLines(w.codexScan())

	if want := []string{"t1 ~/w/notes [approval_policy=never,approvals_reviewer=user,sandbox=danger-full-access] 2026-11-22"}; !slices.Equal(got, want) {
		t.Errorf("sessions = %q, want %q", got, want)
	}
}

func TestAGranularPolicyIsNamedNotSpelledOut(t *testing.T) {
	w := newWorld(t)
	granular := map[string]any{"granular": map[string]any{"sandbox_approval": false, "rules": false}}
	w.write(day+"rollout-a-t1.jsonl", meta("/w/p")+turn(granular, "auto_review", "workspace-write"))

	got := w.sessionLines(w.codexScan())

	if want := []string{"t1 ~/w/p [approval_policy=granular,approvals_reviewer=auto_review,sandbox=workspace-write] 2026-11-22"}; !slices.Equal(got, want) {
		t.Errorf("sessions = %q, want %q", got, want)
	}
}

func TestAResumedSessionMergesAcrossRollouts(t *testing.T) {
	w := newWorld(t)
	// Codex replays into a new rollout on resume, and a sub-agent's
	// rollout carries its parent's session_id.
	w.write(day+"rollout-a-t1.jsonl", meta("/w/p")+turn("on-request", "user", "workspace-write"))
	w.write(day+"rollout-b-t1.jsonl", meta("/w/p")+turn("on-request", "user", "workspace-write")+turn("never", "user", "workspace-write"))
	w.write(day+"rollout-c-t2.jsonl", subMeta("t2", "t1", "/w/p")+turn("on-request", "auto_review", "read-only"))

	got := w.sessionLines(w.codexScan())

	want := []string{"t1 ~/w/p [approval_policy=on-request,approvals_reviewer=user,sandbox=workspace-write,approval_policy=never,approvals_reviewer=auto_review,sandbox=read-only] 2026-11-22"}
	if !slices.Equal(got, want) {
		t.Errorf("sessions = %q, want %q: one session, every mode it ran in", got, want)
	}
}

func TestAModeValueThatIsntOneIsntKept(t *testing.T) {
	w := newWorld(t)
	w.write(day+"rollout-a-t1.jsonl", meta("/w/p")+turn("never; echo leaked", "user", "read only with spaces"))

	if got, want := w.sessionLines(w.codexScan()), []string{"t1 ~/w/p [approvals_reviewer=user] 2026-11-22"}; !slices.Equal(got, want) {
		t.Errorf("sessions = %q, want %q", got, want)
	}
}

func TestARolloutLeakIsMasked(t *testing.T) {
	w := newWorld(t)
	w.write(day+"rollout-a-t1.jsonl", meta("/w/p")+said("my key is "+token))

	res := w.codexScan()

	if got := ruleIDs(res.Findings); !slices.Equal(got, []string{TranscriptLeak().ID}) {
		t.Fatalf("findings = %q, want one leak", got)
	}
	f := res.Findings[0]
	if f.Origin.Agent != "codex" || f.Origin.Line != 2 || strings.Contains(f.Evidence.String(), token) {
		t.Errorf("leak = %s line %d %q, want codex, line 2, masked", f.Origin.Agent, f.Origin.Line, f.Evidence)
	}
}

func compress(t *testing.T, s string) string {
	t.Helper()
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enc.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestACompressedRolloutIsReadWholeOnce(t *testing.T) {
	w := newWorld(t)
	name := day + "rollout-a-t1.jsonl.zst"
	w.write(name, compress(t, meta("/w/p")+turn("never", "user", "workspace-write")+said(token)))

	first := w.codexScan()
	second := w.codexScan()

	want := []string{"t1 ~/w/p [approval_policy=never,approvals_reviewer=user,sandbox=workspace-write] 2026-11-22"}
	if got := w.sessionLines(first); !slices.Equal(got, want) {
		t.Errorf("sessions = %q, want %q", got, want)
	}
	if got := w.sessionLines(second); !slices.Equal(got, want) || second.Read != 0 || len(second.Findings) != 1 {
		t.Errorf("second scan: sessions %q, read %d lines, %d findings; want the same results from the cursor, nothing read", got, second.Read, len(second.Findings))
	}

	w.write(name, compress(t, meta("/w/p")+turn("on-request", "user", "read-only")))
	third := w.codexScan()
	if got, want := w.sessionLines(third), []string{"t1 ~/w/p [approval_policy=on-request,approvals_reviewer=user,sandbox=read-only] 2026-11-22"}; !slices.Equal(got, want) {
		t.Errorf("after a rewrite: sessions = %q, want %q", got, want)
	}
}

func TestABrokenCompressedRolloutIsSkipped(t *testing.T) {
	w := newWorld(t)
	w.write(day+"rollout-a-t1.jsonl.zst", "not zstd at all")

	res := w.codexScan()

	if len(res.Sessions) != 0 || len(res.Findings) != 0 {
		t.Errorf("sessions %q, findings %q, want neither: a bad file is skipped, never an error", w.sessionLines(res), ruleIDs(res.Findings))
	}
}

func TestCodexHistoryJSONLIsCheckedForLeaksOnly(t *testing.T) {
	w := newWorld(t)
	w.write(".codex/history.jsonl", `{"session_id":"t1","ts":1763805600,"text":"export K=`+token+`"}`+"\n")

	res := w.codexScan()

	if len(res.Sessions) != 0 || !slices.Equal(ruleIDs(res.Findings), []string{TranscriptLeak().ID}) {
		t.Errorf("sessions %q, findings %q, want only the leak", w.sessionLines(res), ruleIDs(res.Findings))
	}
}

// db makes a SQLite file in the fake home and runs stmts in it.
func (w *world) db(rel string, stmts ...string) string {
	w.t.Helper()
	path := filepath.Join(w.home, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		w.t.Fatal(err)
	}
	con, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		w.t.Fatal(err)
	}
	defer func() { _ = con.Close() }()
	for _, s := range stmts {
		if _, err := con.ExecContext(w.t.Context(), s); err != nil {
			w.t.Fatalf("%s: %v", s, err)
		}
	}
	return path
}

func TestTheStateDBAddsSessions(t *testing.T) {
	w := newWorld(t)
	w.db(".codex/state_5.sqlite",
		`create table threads (id text, rollout_path text, cwd text, approval_mode text, sandbox_policy text, updated_at_ms integer, title text)`,
		`insert into threads values ('t9', '', '/w/x', 'never', '{"type":"danger-full-access"}', 1763805600000, 'secret plans')`)

	got := w.sessionLines(w.codexScan())

	if want := []string{"t9 ~/w/x [approval_policy=never,sandbox=danger-full-access] 2025-11-22"}; !slices.Equal(got, want) {
		t.Errorf("sessions = %q, want %q", got, want)
	}
}

func TestAStateDBWithAnotherShapeIsUnknownNotAnError(t *testing.T) {
	w := newWorld(t)
	w.db(".codex/state_5.sqlite", `create table threads (id text, something_else text)`, `insert into threads values ('t9', 'x')`)
	w.db(".codex/state_6.sqlite", `create table other (x text)`)
	w.write(".codex/state_7.sqlite", "not a database")

	res := w.codexScan()

	if got, want := w.sessionLines(res), []string{"t9  [] undated"}; !slices.Equal(got, want) || len(res.Findings) != 0 {
		t.Errorf("sessions = %q, findings %q; want %q and no findings", got, ruleIDs(res.Findings), want)
	}
}

func TestAMemoryInTheMemoriesDBIsCheckedForLeaks(t *testing.T) {
	w := newWorld(t)
	db := w.db(".codex/memories_1.sqlite",
		`create table stage1_outputs (thread_id text, raw_memory text, rollout_summary text)`,
		`insert into stage1_outputs values ('t1', 'prefers tabs', 'set things up')`,
		`insert into stage1_outputs values ('t2', 'their key is `+token+`', '')`)

	res := w.codexScan()

	if got := ruleIDs(res.Findings); !slices.Equal(got, []string{TranscriptLeak().ID}) {
		t.Fatalf("findings = %q, want one leak", got)
	}
	f := res.Findings[0]
	if f.Origin.File.Raw() != db || !strings.HasPrefix(f.Evidence.String(), "row 2: test_token ") {
		t.Errorf("leak = %s %q, want %s, row 2", f.Origin.File.Raw(), f.Evidence, db)
	}
}

func TestALockedDBIsSkippedWithANote(t *testing.T) {
	w := newWorld(t)
	path := w.db(".codex/state_5.sqlite", `create table threads (id text, cwd text)`, `insert into threads values ('t9', '/w/x')`)
	// Another process holds a write lock: in rollback-journal mode that
	// blocks readers too.
	con, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = con.Close() })
	con.SetMaxOpenConns(1)
	if _, err := con.ExecContext(t.Context(), `begin exclusive`); err != nil {
		t.Fatal(err)
	}

	res := w.codexScan()

	if got := ruleIDs(res.Findings); !slices.Equal(got, []string{Locked().ID}) {
		t.Errorf("findings = %q, want %s", got, Locked().ID)
	}
	if _, err := con.ExecContext(t.Context(), `rollback`); err != nil {
		t.Fatal(err)
	}
}

func TestOpeningADBChangesNothingOnDisk(t *testing.T) {
	w := newWorld(t)
	path := w.db(".codex/state_5.sqlite", `create table threads (id text, cwd text)`, `insert into threads values ('t9', '/w/x')`)
	before, err := os.ReadFile(path) //nolint:gosec // G304: the test's own fixture
	if err != nil {
		t.Fatal(err)
	}

	w.codexScan()

	after, err := os.ReadFile(path) //nolint:gosec // G304: the test's own fixture
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !bytes.Equal(before, after) || !slices.Equal(names, []string{"state_5.sqlite"}) {
		t.Errorf("after a scan: same bytes %v, dir %q; want the file untouched and nothing new next to it", bytes.Equal(before, after), names)
	}
}

func TestSqliteHomeMovesTheDBs(t *testing.T) {
	w := newWorld(t)
	w.db("dbs/state_5.sqlite", `create table threads (id text, cwd text)`, `insert into threads values ('t9', '/w/x')`)
	c := w.context()
	cur := Cursor{}

	res := Codex(c, &cur, filepath.Join(c.Env.Home, ".codex"), filepath.Join(c.Env.Home, "dbs"))

	if got, want := w.sessionLines(res), []string{"t9 ~/w/x [] undated"}; !slices.Equal(got, want) {
		t.Errorf("sessions = %q, want %q", got, want)
	}
}

// dsnFor is checked on its own: Windows paths, spaces and # in a path must
// all reach the driver as the same file.
func TestTheDSNKeepsOddPathsIntact(t *testing.T) {
	for _, p := range []string{`C:\Users\Some One\.codex\state_5.sqlite`, "/home/a b/#x/state_5.sqlite"} {
		u, err := url.Parse(dsnFor(p))
		if err != nil {
			t.Fatalf("dsnFor(%q) doesn't parse: %v", p, err)
		}
		if !strings.Contains(u.RawQuery, "mode=ro") || !strings.Contains(u.RawQuery, "query_only") {
			t.Errorf("dsnFor(%q) = %q, want read-only and query_only", p, dsnFor(p))
		}
		if got := strings.TrimPrefix(u.Path, "/"); filepath.FromSlash(got) != filepath.FromSlash(strings.TrimPrefix(filepath.ToSlash(p), "/")) {
			t.Errorf("dsnFor(%q) path = %q, want the same file", p, u.Path)
		}
	}
}

func TestOneSecretInBothColumnsOfARowIsOneLeak(t *testing.T) {
	w := newWorld(t)
	w.db(".codex/memories_1.sqlite",
		`create table stage1_outputs (thread_id text, raw_memory text, rollout_summary text)`,
		`insert into stage1_outputs values ('t1', 'key `+token+`', 'used `+token+`')`)

	if got := ruleIDs(w.codexScan().Findings); len(got) != 1 {
		t.Errorf("findings = %q, want one leak for one secret in one row", got)
	}
}

func TestATooLargeCompressedRolloutIsSkippedWithANote(t *testing.T) {
	w := newWorld(t)
	old := maxFileSize
	maxFileSize = 16
	t.Cleanup(func() { maxFileSize = old })
	w.write(day+"rollout-a-t1.jsonl.zst", compress(t, meta("/w/p")+said(token)))

	res := w.codexScan()

	if got := ruleIDs(res.Findings); !slices.Equal(got, []string{TooLarge().ID}) || len(res.Sessions) != 0 {
		t.Errorf("findings = %q, sessions %q; want only %s", got, w.sessionLines(res), TooLarge().ID)
	}
}

func TestADBFsysWouldRefuseIsNeverOpened(t *testing.T) {
	w := newWorld(t)
	// A real database outside the fake home, reached by a link inside it.
	outside := filepath.Join(t.TempDir(), "state_5.sqlite")
	con, err := sql.Open("sqlite", "file:"+filepath.ToSlash(outside))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`create table threads (id text, cwd text)`, `insert into threads values ('t9', '/w/x')`} {
		if _, err := con.ExecContext(t.Context(), s); err != nil {
			t.Fatal(err)
		}
	}
	_ = con.Close()
	link := filepath.Join(w.home, ".codex", "state_5.sqlite")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("can't make symlinks here: %v", err)
	}

	if res := w.codexScan(); len(res.Sessions) != 0 {
		t.Errorf("sessions = %q, want none: the database is outside the fake home", w.sessionLines(res))
	}
}
