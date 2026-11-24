package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
)

// The fake token matches the test scrubber's pattern. Made up.
const token = "tok_Hq7Lm2Pz9Rw4Tb8Nc1Vd" //nolint:gosec // G101: a made-up test token

type world struct {
	t    *testing.T
	home string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	return &world{t: t, home: t.TempDir()}
}

func (w *world) write(rel, content string) string {
	w.t.Helper()
	p := filepath.Join(w.home, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		w.t.Fatal(err)
	}
	return p
}

func (w *world) appendTo(rel, content string) {
	w.t.Helper()
	f, err := os.OpenFile(filepath.Join(w.home, filepath.FromSlash(rel)), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		w.t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(content); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) context() agent.Context {
	w.t.Helper()
	env, err := platform.FromHome(w.home)
	if err != nil {
		w.t.Fatal(err)
	}
	f, err := fsys.New(env)
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() { _ = f.Close() })
	s, err := redact.New([]redact.Pattern{
		{Kind: "test_token", Re: regexp.MustCompile(`tok_[A-Za-z0-9]{16,}`)},
		{Kind: "test_low", Re: regexp.MustCompile(`low_[a]{16,}`), MinEntropy: 1}, // all one letter: a placeholder
	}, fixedKey("0123456789abcdef0123456789abcdef"))
	if err != nil {
		w.t.Fatal(err)
	}
	return agent.Context{Env: env, Files: f, Scrub: s}
}

// scan runs one scan the way the CLI does: load the cursor, read, save.
func (w *world) scan() Result {
	w.t.Helper()
	c := w.context()
	cur := Load(c.Env)
	res := Claude(c, &cur, filepath.Join(c.Env.Home, ".claude"))
	if err := cur.Save(c.Env); err != nil {
		w.t.Fatal(err)
	}
	return res
}

func rec(fields ...string) string { return "{" + strings.Join(fields, ",") + "}\n" }

func (w *world) sessionLines(res Result) []string {
	out := make([]string, 0, len(res.Sessions))
	for _, s := range res.Sessions {
		modes := make([]string, 0, len(s.Modes))
		for _, m := range s.Modes {
			modes = append(modes, m.String())
		}
		date := "undated"
		if !s.LastTime().IsZero() {
			date = s.LastTime().Format("2006-01-02")
		}
		cwd := s.CWD.Raw()
		if rel, err := filepath.Rel(w.context().Env.Home, cwd); err == nil && filepath.IsLocal(rel) {
			cwd = "~/" + filepath.ToSlash(rel)
		}
		out = append(out, s.ID.String()+" "+cwd+" ["+strings.Join(modes, ",")+"] "+date)
	}
	slices.Sort(out)
	return out
}

func ruleIDs(fs []finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

const sid = `"sessionId":"s1"`

// fixedKey gives the scrubber a fingerprint key without touching disk.
type fixedKey []byte

func (k fixedKey) Key() ([]byte, error) { return k, nil }

func TestTheRealCwdComesFromTheRecords(t *testing.T) {
	w := newWorld(t)
	// The folder name is lossy: d--my-project could be d:\my-project or
	// d:\my\project. The records say which.
	w.write(".claude/projects/d--my-project/s1.jsonl",
		rec(`"type":"user"`, sid, `"cwd":"d:\\my\\project"`, `"timestamp":"2026-11-20T10:00:00Z"`, `"permissionMode":"default"`))

	got := w.sessionLines(w.scan())

	if want := []string{"s1 ~/my/project [default] 2026-11-20"}; !slices.Equal(got, want) {
		t.Errorf("sessions = %q, want %q", got, want)
	}
}

func TestADriveLetterIsUpperCased(t *testing.T) {
	// The notes say one session's records mix d:\ and D:\.
	for in, want := range map[string]string{`d:\my\project`: `D:\my\project`, `D:\x`: `D:\x`, "/w/p": "/w/p", "": ""} {
		if got := upperDrive(in); got != want {
			t.Errorf("upperDrive(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestModesComeFromModeRecordsAndPrompts(t *testing.T) {
	w := newWorld(t)
	w.write(".claude/projects/p/s1.jsonl",
		rec(`"type":"permission-mode"`, sid, `"permissionMode":"bypassPermissions"`)+
			rec(`"type":"user"`, sid, `"cwd":"/w/p"`, `"permissionMode":"bypassPermissions"`, `"timestamp":"2026-11-20T10:00:00Z"`)+
			rec(`"type":"permission-mode"`, sid, `"permissionMode":"default"`)+
			rec(`"type":"user"`, sid, `"cwd":"/w/p"`, `"permissionMode":"default"`, `"timestamp":"2026-11-21T10:00:00Z"`)+
			// Replay: the same records again, older timestamps and all.
			rec(`"type":"permission-mode"`, sid, `"permissionMode":"bypassPermissions"`)+
			rec(`"type":"user"`, sid, `"cwd":"/w/p"`, `"permissionMode":"bypassPermissions"`, `"timestamp":"2026-11-20T10:00:00Z"`))

	got := w.sessionLines(w.scan())

	if want := []string{"s1 ~/w/p [bypassPermissions,default] 2026-11-21"}; !slices.Equal(got, want) {
		t.Errorf("sessions = %q, want %q: each mode once, the newest timestamp", got, want)
	}
}

func TestASessionWithNoTimestampIsUndated(t *testing.T) {
	w := newWorld(t)
	w.write(".claude/projects/p/s1.jsonl", rec(`"type":"user"`, sid, `"cwd":"/w/p"`, `"permissionMode":"auto"`))

	if got, want := w.sessionLines(w.scan()), []string{"s1 ~/w/p [auto] undated"}; !slices.Equal(got, want) {
		t.Errorf("sessions = %q, want %q", got, want)
	}
}

func TestOddLinesAndOddFieldsAreSkipped(t *testing.T) {
	w := newWorld(t)
	w.write(".claude/projects/p/s1.jsonl",
		"not json\n"+
			`[1,2,3]`+"\n"+
			rec(`"type":"user"`, sid, `"cwd":{"not":"a string"}`, `"permissionMode":7`)+
			rec(`"type":"user"`, sid, `"cwd":"/w/p"`, `"toolUseResult":"a bare string"`, `"permissionMode":"plan"`))

	res := w.scan()

	if got, want := w.sessionLines(res), []string{"s1 ~/w/p [plan] undated"}; !slices.Equal(got, want) {
		t.Errorf("sessions = %q, want %q", got, want)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings = %q, want none: an odd line is never an error", ruleIDs(res.Findings))
	}
}

func TestAFileWithNoSessionIDTakesItsName(t *testing.T) {
	w := newWorld(t)
	w.write(".claude/projects/p/abc-123.jsonl", rec(`"type":"user"`, `"cwd":"/w/p"`))

	if got, want := w.sessionLines(w.scan()), []string{"abc-123 ~/w/p [] undated"}; !slices.Equal(got, want) {
		t.Errorf("sessions = %q, want %q: the docs name transcripts <session-id>.jsonl", got, want)
	}
}

func TestOnlyTopLevelTranscriptsAreSessions(t *testing.T) {
	w := newWorld(t)
	w.write(".claude/projects/p/s1.jsonl", rec(`"type":"user"`, sid, `"cwd":"/w/p"`))
	w.write(".claude/projects/p/s1.orphaned-1700000000-ab.jsonl", rec(`"type":"user"`, sid, `"cwd":"/w/p"`, `"permissionMode":"auto"`))
	w.write(".claude/projects/p/s1/subagents/agent-1.jsonl", rec(`"type":"user"`, `"sessionId":"sub"`, `"cwd":"/w/p"`))
	w.write(".claude/projects/p/memory/MEMORY.md", "notes\n")

	if got, want := w.sessionLines(w.scan()), []string{"s1 ~/w/p [auto] undated"}; !slices.Equal(got, want) {
		t.Errorf("sessions = %q, want %q: the set-aside copy is the same session, subagents and memory aren't sessions", got, want)
	}
}

func TestALeakIsMaskedWithItsLine(t *testing.T) {
	w := newWorld(t)
	file := w.write(".claude/projects/p/s1.jsonl",
		rec(`"type":"user"`, sid, `"cwd":"/w/p"`)+
			rec(`"type":"user"`, sid, `"message":{"content":"use `+token+` please"}`))

	res := w.scan()

	if got := ruleIDs(res.Findings); !slices.Equal(got, []string{TranscriptLeak().ID}) {
		t.Fatalf("findings = %q, want one %s", got, TranscriptLeak().ID)
	}
	f := res.Findings[0]
	if f.Origin.Line != 2 || !strings.EqualFold(f.Origin.File.Raw(), file) || !f.Origin.Observed {
		t.Errorf("origin = %s line %d observed %v, want %s line 2, observed", f.Origin.File.Raw(), f.Origin.Line, f.Origin.Observed, file)
	}
	if ev := f.Evidence.String(); strings.Contains(ev, token) || !strings.HasPrefix(ev, "line 2: test_token REDACTED:test_token:") {
		t.Errorf("evidence = %q, want the line and type up front (a long session path gets cut before its :line), never the value", ev)
	}
}

func TestHistoryJSONLIsCheckedForLeaksOnly(t *testing.T) {
	w := newWorld(t)
	w.write(".claude/history.jsonl", rec(`"display":"export X=`+token+`"`, `"project":"/w/p"`))

	res := w.scan()

	if len(res.Sessions) != 0 {
		t.Errorf("sessions = %q, want none: history.jsonl holds prompts, not sessions", w.sessionLines(res))
	}
	if got := ruleIDs(res.Findings); !slices.Equal(got, []string{TranscriptLeak().ID}) {
		t.Errorf("findings = %q, want the leak", got)
	}
}

func TestASecondScanReadsOnlyNewLinesAndKeepsTheOld(t *testing.T) {
	w := newWorld(t)
	w.write(".claude/projects/p/s1.jsonl",
		rec(`"type":"user"`, sid, `"cwd":"/w/p"`, `"permissionMode":"auto"`)+
			rec(`"type":"user"`, sid, `"message":"`+token+`"`))
	first := w.scan()

	w.appendTo(".claude/projects/p/s1.jsonl", rec(`"type":"user"`, sid, `"permissionMode":"plan"`, `"timestamp":"2026-11-22T10:00:00Z"`))
	second := w.scan()

	if got, want := w.sessionLines(second), []string{"s1 ~/w/p [auto,plan] 2026-11-22"}; !slices.Equal(got, want) {
		t.Errorf("sessions = %q, want %q: the old modes carried forward, the new one added", got, want)
	}
	if len(first.Findings) != 1 || len(second.Findings) != 1 || second.Findings[0].Origin.Line != 2 {
		t.Errorf("leaks = %d then %d, want the line 2 leak carried forward once", len(first.Findings), len(second.Findings))
	}
	if second.Read != 1 {
		t.Errorf("second scan read %d lines, want only the 1 new one", second.Read)
	}
}

func TestAPartLineWaitsForTheNextScan(t *testing.T) {
	w := newWorld(t)
	w.write(".claude/projects/p/s1.jsonl", rec(`"type":"user"`, sid, `"cwd":"/w/p"`)+`{"type":"user",`+sid+`,"permissionMode":"au`)
	first := w.scan()

	w.appendTo(".claude/projects/p/s1.jsonl", "to\"}\n")
	second := w.scan()

	if got, want := w.sessionLines(first), []string{"s1 ~/w/p [] undated"}; !slices.Equal(got, want) {
		t.Errorf("first sessions = %q, want %q: a line still being written isn't read", got, want)
	}
	if got, want := w.sessionLines(second), []string{"s1 ~/w/p [auto] undated"}; !slices.Equal(got, want) {
		t.Errorf("second sessions = %q, want %q", got, want)
	}
}

func TestARewrittenFileIsReadAgainFromTheStart(t *testing.T) {
	w := newWorld(t)
	w.write(".claude/projects/p/s1.jsonl", rec(`"type":"user"`, sid, `"cwd":"/w/p"`, `"permissionMode":"bypassPermissions"`))
	w.scan()

	// Same size or bigger, but a different start: the cursor's head hash
	// catches it, and the old results go.
	w.write(".claude/projects/p/s1.jsonl", rec(`"type":"user"`, sid, `"cwd":"/w/q"`, `"permissionMode":"defaultxxxxxxxxxxxx"`))
	second := w.scan()

	if got, want := w.sessionLines(second), []string{"s1 ~/w/q [defaultxxxxxxxxxxxx] undated"}; !slices.Equal(got, want) {
		t.Errorf("sessions = %q, want %q: nothing kept from the old contents", got, want)
	}
}

func TestAShrunkFileIsReadAgain(t *testing.T) {
	w := newWorld(t)
	w.write(".claude/projects/p/s1.jsonl",
		rec(`"type":"user"`, sid, `"cwd":"/w/p"`)+rec(`"type":"user"`, sid, `"permissionMode":"auto"`))
	w.scan()

	w.write(".claude/projects/p/s1.jsonl", rec(`"type":"user"`, sid, `"cwd":"/w/p"`))
	second := w.scan()

	if got, want := w.sessionLines(second), []string{"s1 ~/w/p [] undated"}; !slices.Equal(got, want) {
		t.Errorf("sessions = %q, want %q", got, want)
	}
}

func TestADeletedFileTakesItsResultsWithIt(t *testing.T) {
	w := newWorld(t)
	p := w.write(".claude/projects/p/s1.jsonl", rec(`"type":"user"`, sid, `"message":"`+token+`"`))
	w.scan()

	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	second := w.scan()

	if len(second.Sessions) != 0 || len(second.Findings) != 0 {
		t.Errorf("after delete: %d sessions, findings %q, want none", len(second.Sessions), ruleIDs(second.Findings))
	}
}

func TestTheCursorHoldsNoContent(t *testing.T) {
	w := newWorld(t)
	w.write(".claude/projects/p/s1.jsonl",
		rec(`"type":"user"`, sid, `"cwd":"/w/p"`, `"message":{"content":"secret plans and `+token+`"}`))
	w.scan()

	data, err := os.ReadFile(filepath.Join(w.home, platform.StateDirName, cursorFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{token, "secret plans", "content"} {
		if strings.Contains(string(data), leak) {
			t.Errorf("cursor holds %q:\n%s", leak, data)
		}
	}
}

func TestABrokenCursorStartsOver(t *testing.T) {
	w := newWorld(t)
	w.write(".claude/projects/p/s1.jsonl", rec(`"type":"user"`, sid, `"cwd":"/w/p"`))
	w.write(platform.StateDirName+"/"+cursorFile, "{not json")

	if got, want := w.sessionLines(w.scan()), []string{"s1 ~/w/p [] undated"}; !slices.Equal(got, want) {
		t.Errorf("sessions = %q, want %q", got, want)
	}
}

func TestClaudeConfigDirMovesTheHistory(t *testing.T) {
	w := newWorld(t)
	w.write("elsewhere/projects/p/s1.jsonl", rec(`"type":"user"`, sid, `"cwd":"/w/p"`))
	c := w.context()
	cur := Cursor{}

	res := Claude(c, &cur, filepath.Join(c.Env.Home, "elsewhere"))

	if got, want := w.sessionLines(res), []string{"s1 ~/w/p [] undated"}; !slices.Equal(got, want) {
		t.Errorf("sessions = %q, want %q", got, want)
	}
	if res.Sessions[0].Agent != model.AgentClaude {
		t.Errorf("agent = %s, want claude", res.Sessions[0].Agent)
	}
}

func TestNoHistoryWritesNoCursor(t *testing.T) {
	w := newWorld(t)
	w.scan()

	if _, err := os.Stat(filepath.Join(w.home, platform.StateDirName)); !os.IsNotExist(err) {
		t.Errorf("state dir stat = %v, want nothing written: there's no history to remember", err)
	}
}

func TestTheLastFileGoneStillPrunesTheCursor(t *testing.T) {
	w := newWorld(t)
	p := w.write(".claude/projects/p/s1.jsonl", rec(`"type":"user"`, sid, `"cwd":"/w/p"`))
	w.scan()
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	w.scan()

	data, err := os.ReadFile(filepath.Join(w.home, platform.StateDirName, cursorFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "s1.jsonl") {
		t.Errorf("cursor still names the deleted file:\n%s", data)
	}
}

func TestAFakeHomesCwdMapsIntoTheHome(t *testing.T) {
	w := newWorld(t)
	w.write(".claude/projects/-projects-app/s1.jsonl", rec(`"type":"user"`, sid, `"cwd":"/projects/app"`))

	res := w.scan()

	if want := filepath.Join(w.context().Env.Home, "projects", "app"); len(res.Sessions) != 1 || res.Sessions[0].CWD.Raw() != want {
		t.Errorf("sessions = %q, want the cwd at %s, like every agent record under --home", w.sessionLines(res), want)
	}
}

func TestAFileCutBelowItsOffsetIsReadAgain(t *testing.T) {
	w := newWorld(t)
	// Over 4 KB, so the cut keeps the hashed head the same: only the size
	// says the file changed.
	long := rec(`"type":"user"`, sid, `"cwd":"/w/p"`, `"pad":"`+strings.Repeat("x", 5000)+`"`)
	w.write(".claude/projects/p/s1.jsonl", long+rec(`"type":"user"`, sid, `"permissionMode":"auto"`))
	w.scan()

	w.write(".claude/projects/p/s1.jsonl", long)
	second := w.scan()

	if got, want := w.sessionLines(second), []string{"s1 ~/w/p [] undated"}; !slices.Equal(got, want) {
		t.Errorf("sessions = %q, want %q: the auto line is gone", got, want)
	}
}

func TestATooLargeFileIsSkippedWithANote(t *testing.T) {
	w := newWorld(t)
	old := maxFileSize
	maxFileSize = 64
	t.Cleanup(func() { maxFileSize = old })
	w.write(".claude/projects/p/s1.jsonl", rec(`"type":"user"`, sid, `"cwd":"/w/p"`, `"message":"`+token+` and then some more text"`))

	res := w.scan()

	if got := ruleIDs(res.Findings); !slices.Equal(got, []string{TooLarge().ID}) {
		t.Errorf("findings = %q, want only %s: nothing in it is read", got, TooLarge().ID)
	}
	if len(res.Sessions) != 0 {
		t.Errorf("sessions = %q, want none", w.sessionLines(res))
	}
}

func TestAPlaceholderIsntALeak(t *testing.T) {
	w := newWorld(t)
	w.write(".claude/projects/p/s1.jsonl", rec(`"type":"user"`, sid, `"message":"set it to low_aaaaaaaaaaaaaaaaaaaa"`))

	if got := ruleIDs(w.scan().Findings); len(got) != 0 {
		t.Errorf("findings = %q, want none for a placeholder", got)
	}
}

func TestAModeThatIsntOneIsntKept(t *testing.T) {
	w := newWorld(t)
	w.write(".claude/projects/p/s1.jsonl",
		rec(`"type":"user"`, sid, `"cwd":"/w/p"`, `"permissionMode":"default; echo leaked words"`)+
			rec(`"type":"user"`, sid, `"permissionMode":"plan"`))

	if got, want := w.sessionLines(w.scan()), []string{"s1 ~/w/p [plan] undated"}; !slices.Equal(got, want) {
		t.Errorf("sessions = %q, want %q: only a mode-shaped value reaches the cursor", got, want)
	}
}

func TestACursorFromAnotherVersionStartsOver(t *testing.T) {
	w := newWorld(t)
	p := w.write(".claude/projects/p/s1.jsonl", rec(`"type":"user"`, sid, `"cwd":"/w/p"`, `"permissionMode":"auto"`))
	// A cursor that claims the whole file was read already, and found
	// nothing. From another version, it can't be trusted.
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	size := strconv.FormatInt(info.Size(), 10) // read to the end, so only the version gives it away
	w.write(platform.StateDirName+"/"+cursorFile, `{"version":99,"files":{`+jsonString(p)+`:{"size":`+size+`,"offset":`+size+`,"lines":1}}}`)

	if got, want := w.sessionLines(w.scan()), []string{"s1 ~/w/p [auto] undated"}; !slices.Equal(got, want) {
		t.Errorf("sessions = %q, want %q", got, want)
	}
}

func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err) // a string always marshals
	}
	return string(b)
}

func TestALeakGoesOnItsSession(t *testing.T) {
	w := newWorld(t)
	w.write(".claude/projects/p/s1.jsonl", rec(`"type":"user"`, sid, `"cwd":"/w/p"`)+rec(`"type":"user"`, sid, `"message":"`+token+`"`))
	w.write(".claude/projects/p/s2.jsonl", rec(`"type":"user"`, `"sessionId":"s2"`, `"cwd":"/w/p"`))

	res := w.scan()

	got := map[string]int{}
	for _, s := range res.Sessions {
		got[s.ID.String()] = len(s.Secrets)
		for _, sec := range s.Secrets {
			if !strings.HasPrefix(sec.String(), "test_token, fingerprint ") || strings.Contains(sec.String(), token) {
				t.Errorf("secret = %q, want its kind and fingerprint, never the value", sec)
			}
		}
	}
	if got["s1"] != 1 || got["s2"] != 0 {
		t.Errorf("secrets per session = %v, want s1 1 and s2 none", got)
	}
}
