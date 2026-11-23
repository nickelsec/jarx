package report

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

type scanFixture struct {
	t    *testing.T
	s    *redact.Scrubber
	home string
}

func newScanFixture(t *testing.T) scanFixture {
	t.Helper()
	s, err := redact.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return scanFixture{t: t, s: s, home: filepath.FromSlash("/home/dev")}
}

func (f scanFixture) path(rel string) model.Path {
	return model.NewPath(f.s, filepath.Join(f.home, filepath.FromSlash(rel)))
}

func (f scanFixture) text(v string) redact.Text {
	t, _ := f.s.Scrub(v)
	return t
}

func (f scanFixture) finding(id string, sev finding.Severity, file, evidence string) finding.Finding {
	return finding.Finding{RuleID: id, Severity: sev, Origin: model.Origin{File: f.path(file)}, Evidence: f.text(evidence)}
}

func (f scanFixture) rules(n int) *finding.Registry {
	f.t.Helper()
	var rs []finding.Rule
	for i := 1; i <= n; i++ {
		rs = append(rs, finding.Rule{ID: "JARX-TEST-" + pad3(i), Severity: finding.Info, Title: "rule number " + pad3(i), Fix: "fix it"})
	}
	r, err := finding.NewRegistry(rs...)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

func pad3(i int) string { return fmt.Sprintf("%03d", i) }

func (f scanFixture) view(fs ...finding.Finding) ScanView {
	return ScanView{
		Fake: true, Home: model.NewPath(f.s, f.home), GOOS: "linux",
		Agents: []AgentInfo{
			{Agent: model.AgentClaude, Name: "Claude Code", ConfigDir: f.path(".claude"), Found: true},
			{Agent: model.AgentCodex, Name: "Codex", ConfigDir: f.path(".codex")},
		},
		Projects: []model.Project{{
			Path: f.path("app"), Status: model.ProjectOK,
			Origins: []model.Origin{{Agent: model.AgentClaude}},
			Trust:   []model.Trust{{Level: model.TrustTrusted, Origin: model.Origin{Agent: model.AgentClaude}}},
		}},
		Findings: fs, Rules: f.rules(20),
	}
}

func render(st Style, v ScanView) string {
	s, err := redact.New(nil, nil)
	if err != nil {
		panic(err)
	}
	var out bytes.Buffer
	p := New(&out, io.Discard, s)
	p.Style = st
	p.Scan(v)
	return out.String()
}

func TestNoLineIsWiderThanTheTerminal(t *testing.T) {
	f := newScanFixture(t)
	long := strings.Repeat("evidence that goes on ", 20)
	v := f.view(f.finding("JARX-TEST-001", finding.High, "app/CLAUDE.md", long), f.finding("JARX-TEST-002", finding.Info, ".claude/settings.json", long))
	for _, width := range []int{40, 60, 80, 120, 200} {
		for _, uni := range []bool{true, false} {
			for _, all := range []bool{true, false} {
				v.All = all
				for l := range strings.SplitSeq(render(Style{Width: width, Unicode: uni}, v), "\n") {
					if c := cells(l); c > width {
						t.Errorf("width %d (unicode %v, all %v): line is %d wide: %q", width, uni, all, c, l)
					}
				}
			}
		}
	}
}

func TestTheRuleIDSitsRightAfterTheTitle(t *testing.T) {
	f := newScanFixture(t)
	v := f.view(f.finding("JARX-TEST-001", finding.High, "app/CLAUDE.md", "the evidence"))

	for width, want := range map[int]string{
		// Wide: the file and evidence on one line, branching off the title.
		120: "\\- HIGH  Rule number 001  TEST-001\n   \\- CLAUDE.md  the evidence\n",
		// Narrow: the evidence gets its own line.
		60: "\\- HIGH  Rule number 001  TEST-001\n   \\- CLAUDE.md\n      the evidence\n",
		// Too narrow for the ID: it moves down, next to the file.
		30: "\\- HIGH  Rule number 001\n   \\- TEST-001  CLAUDE.md\n      the evidence\n",
	} {
		if out := render(Style{Width: width}, v); !strings.Contains(out, want) {
			t.Errorf("%d columns =\n%s\nwant it to contain\n%s", width, out, want)
		}
	}
}

func TestFindingsHaveABlankLineBetweenThem(t *testing.T) {
	f := newScanFixture(t)
	v := f.view(f.finding("JARX-TEST-001", finding.High, "app/a.md", "one"), f.finding("JARX-TEST-002", finding.High, "app/b.md", "two"))

	out := render(Style{Width: 80}, v)

	if want := "+- HIGH  Rule number 001  TEST-001\n|  \\- a.md  one\n|\n\\- HIGH  Rule number 002"; !strings.Contains(out, want) {
		t.Errorf("output =\n%s\nwant a line with only the tree bar between findings", out)
	}
}

func TestALongListKeepsEveryHighFinding(t *testing.T) {
	f := newScanFixture(t)
	var fs []finding.Finding
	for i := 1; i <= 12; i++ {
		fs = append(fs, f.finding("JARX-TEST-"+pad3(i), finding.High, "app/a.md", "h"))
	}
	for i := 13; i <= 16; i++ {
		fs = append(fs, f.finding("JARX-TEST-"+pad3(i), finding.Info, "app/a.md", "i"))
	}

	out := render(Style{Width: 80}, f.view(fs...))

	if n := strings.Count(out, "HIGH  Rule number"); n != 12 {
		t.Errorf("%d HIGH findings shown, want all 12 even past the cap", n)
	}
	if !strings.Contains(out, "... 4 more: 4 INFO  (jarx scan --all)") {
		t.Errorf("output =\n%s\nwant the four info findings counted", out)
	}
	if all := f.view(fs...); true {
		all.All = true
		if n := strings.Count(render(Style{Width: 80}, all), "INFO  Rule number"); n != 4 {
			t.Errorf("--all shows %d info findings, want 4", n)
		}
	}
}

func TestUserLevelFindingsShowOnceInTheirOwnGroup(t *testing.T) {
	f := newScanFixture(t)
	v := f.view(f.finding("JARX-TEST-001", finding.High, ".claude/settings.json", "user level"), f.finding("JARX-TEST-002", finding.High, "app/CLAUDE.md", "in the project"))
	v.Projects = append(v.Projects, model.Project{Path: f.path("web"), Status: model.ProjectOK, Origins: []model.Origin{{Agent: model.AgentClaude}}})

	out := render(Style{Width: 80}, v)

	if strings.Count(out, "user level") != 1 || !strings.Contains(out, "your user config - applies to every project\n\\- HIGH  Rule number 001") {
		t.Errorf("output =\n%s\nwant the user-level finding once, under its own heading", out)
	}
	if !strings.Contains(out, "~"+string(filepath.Separator)+"web  claude unknown - no findings") {
		t.Errorf("output =\n%s\nwant the other project with no findings", out)
	}
}

func TestAMissingAgentSaysNotFound(t *testing.T) {
	f := newScanFixture(t)

	out := render(Style{Width: 80}, f.view())

	if !strings.Contains(out, "\\- Codex       not found\n") {
		t.Errorf("output =\n%s\nwant Codex not found", out)
	}
}

func TestUnicodeAndColorWhenTheTerminalTakesThem(t *testing.T) {
	f := newScanFixture(t)
	v := f.view(f.finding("JARX-TEST-001", finding.High, "app/CLAUDE.md", "evil\x1b[32m text"))

	out := render(Style{Width: 80, Unicode: true, Color: true}, v)

	if !strings.Contains(out, "└─ ") || strings.Contains(out, "\\- ") {
		t.Errorf("output has ASCII tree glyphs, want box drawing")
	}
	if !strings.Contains(out, "\x1b[31mHIGH\x1b[0m") {
		t.Errorf("output = %q, want HIGH in red", out)
	}
	if !strings.Contains(out, `evil\x1b[32m text`) {
		t.Errorf("output = %q, want the file's own escape shown as text", out)
	}
}

func TestTheInventoryWrapsToTheTerminal(t *testing.T) {
	var out bytes.Buffer
	ww := &wrapWriter{w: &out, width: 30, home: filepath.FromSlash("/home/dev")}
	_, _ = ww.Write([]byte("  short line\n  a line that is much too long for thirty columns " + filepath.FromSlash("/home/dev/app") + "\n"))
	ww.flush()

	for l := range strings.SplitSeq(strings.TrimSuffix(out.String(), "\n"), "\n") {
		if cells(l) > 30 {
			t.Errorf("line %q is %d wide, want at most 30", l, cells(l))
		}
	}
	if !strings.Contains(out.String(), "  short line\n") || !strings.Contains(out.String(), "~"+string(filepath.Separator)+"app") {
		t.Errorf("output =\n%s\nwant short lines kept and the home dir as ~", out.String())
	}
}

func banner(st Style, version string) string {
	s, err := redact.New(nil, nil)
	if err != nil {
		panic(err)
	}
	var out bytes.Buffer
	p := New(&out, io.Discard, s)
	p.Style = st
	v, _ := s.Scrub(version)
	p.Banner(v)
	return out.String()
}

func TestTheBannerIsASCIIWhereTheTreeIs(t *testing.T) {
	for _, uni := range []bool{true, false} {
		out := banner(Style{Width: 80, Unicode: uni}, "v1.0.0")

		block := strings.Contains(out, "\u2588")
		if block != uni || strings.Contains(out, "#") == uni {
			t.Errorf("unicode %v: banner =\n%s\nwant block chars only on a unicode terminal", uni, out)
		}
		if !strings.Contains(out, "\n\n"+tagline+"\n") {
			t.Errorf("banner = %q, want the tagline under it", out)
		}
	}
}

func TestTheVersionSitsNextToTheBanner(t *testing.T) {
	if out := banner(Style{Width: 80}, "v1.0.0"); !strings.Contains(out, "###    ###  v1.0.0\n\n") {
		t.Errorf("banner =\n%s\nwant the version next to its last row", out)
	}
	// A version too long to fit next to it gets its own line, never cut.
	long := "v0.0.0-20261123052331-38873d0fe4fd+dirty"
	if out := banner(Style{Width: 60}, long); !strings.Contains(out, "###    ###\n"+long+"\n\n") {
		t.Errorf("banner =\n%s\nwant the long version on its own line", out)
	}
}

func (f scanFixture) server(name string, start model.StartState) model.Server {
	o := model.Origin{Agent: model.AgentClaude, Scope: model.ScopeProject, File: f.path("app/.mcp.json"), InEffect: start == model.StartYes || start == model.StartMaybe}
	return model.Server{Name: f.text(name), Transport: model.TransportStdio, Command: f.text("node"), Start: start, Origin: o}
}

func TestServersAreCountedAndLoaded(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.Projects[0].Servers = []model.Server{
		f.server("db", model.StartYes), f.server("feed", model.StartMaybe),
		f.server("evil", model.StartUnknown), f.server("old", model.StartNo),
	}

	out := render(Style{Width: 80}, v)

	if !strings.Contains(out, "4 MCP servers") || !strings.Contains(out, "1 not started - 1 approval unknown") {
		t.Errorf("output =\n%s\nwant the servers counted with the ones that don't start noted", out)
	}
	if !strings.Contains(out, "claude 2 MCP servers") {
		t.Errorf("output =\n%s\nwant the two servers that may start in what claude loads", out)
	}
}

func TestTheInventoryListsEveryServer(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.All = true
	old := f.server("old", model.StartNo)
	old.Origin.Why = f.text("blocked by deniedMcpServers")
	v.Projects[0].Servers = []model.Server{f.server("db", model.StartYes), old}

	out := render(Style{Width: 200}, v)

	for _, want := range []string{"claude MCP servers", "db  stdio  node  project, starts", "old  stdio  node  project, not started  not in effect: blocked by deniedMcpServers"} {
		if !strings.Contains(out, want) {
			t.Errorf("output =\n%s\nwant it to contain %q", out, want)
		}
	}
}

func TestTheInventoryShowsProbeStatusAndOffers(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.All = true
	listed := f.server("notes", model.StartYes)
	listed.Status = model.StatusListed
	listed.Offers = []model.Offer{
		{Kind: model.OfferTool, Name: f.text("save_note"), Description: f.text("Saves a note."), Hints: []redact.Text{f.text("destructiveHint")}},
		{Kind: model.OfferPrompt, Name: f.text("summarize")},
	}
	failed := f.server("broken", model.StartYes)
	failed.Status, failed.StatusWhy = model.StatusFailed, f.text("it exited with code 1 before answering")
	v.Projects[0].Servers = []model.Server{listed, failed}

	out := render(Style{Width: 200}, v)

	for _, want := range []string{
		"notes  stdio  node  project, starts, listed",
		"tool  save_note  Saves a note.  destructiveHint",
		"prompt  summarize",
		"broken  stdio  node  project, starts, failed to start: it exited with code 1 before answering",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output =\n%s\nwant it to contain %q", out, want)
		}
	}
}

func TestTheAgentRowCountsItsServers(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.Projects[0].Servers = []model.Server{f.server("a", model.StartYes), f.server("b", model.StartNo)}

	if out := render(Style{Width: 120}, v); !strings.Contains(out, "Claude Code ~"+string(filepath.Separator)+".claude  1 project (1 trusted) - 2 MCP servers") {
		t.Errorf("output =\n%s\nwant the server count on the Claude row", out)
	}
}

func TestTheInventoryShowsWhetherTheAgentCanCallEachTool(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.All = true
	srv := f.server("github", model.StartYes)
	srv.Status = model.StatusListed
	srv.Offers = []model.Offer{
		{Kind: model.OfferTool, Name: f.text("delete_repo"), Access: model.AccessNoAsk, AccessWhy: f.text("allowed by mcp__github__* in ~/.claude/settings.json")},
		{Kind: model.OfferPrompt, Name: f.text("summarize")},
	}
	v.Projects[0].Servers = []model.Server{srv}

	out := render(Style{Width: 200}, v)

	if want := "tool  delete_repo  agent: runs without asking, allowed by mcp__github__* in ~/.claude/settings.json"; !strings.Contains(out, want) {
		t.Errorf("output =\n%s\nwant it to contain %q", out, want)
	}
	if strings.Contains(out, "summarize  agent:") {
		t.Error("a prompt has no tool access to show")
	}
}
