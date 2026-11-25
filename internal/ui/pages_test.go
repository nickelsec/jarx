package ui

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nickelsec/jarx/internal/catalog"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/llm"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
	"github.com/nickelsec/jarx/internal/report"
	"github.com/nickelsec/jarx/internal/snapshot"
)

type fixture struct {
	t *testing.T
	s *redact.Scrubber
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	ps, err := catalog.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	s, err := redact.New(ps, nil)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{t: t, s: s}
}

func (f fixture) text(v string) redact.Text {
	t, _ := f.s.Scrub(v)
	return t
}

func (f fixture) path(p string) model.Path { return model.NewPath(f.s, p) }

func (f fixture) finding(rule string, sev finding.Severity, agent model.Agent, file, evidence string) finding.Finding {
	return finding.Finding{RuleID: rule, Severity: sev, Evidence: f.text(evidence),
		Origin: model.Origin{Agent: agent, Scope: model.ScopeProject, File: f.path(file), InEffect: true}}
}

const canaryToken = "ghp_Zq9Xw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0Fe9Dc8" //nolint:gosec // G101: a made-up canary

// data is two projects and four findings: a high and an info in tools, a
// medium in app, and a high in the user config.
func (f fixture) data() Data {
	rules, err := finding.NewRegistry(
		finding.Rule{ID: "JARX-POISON-006", Severity: finding.High, Title: "Tool text is aimed at the agent", Detail: "a tool description tells the agent what to do", Fix: "remove the server"},
		finding.Rule{ID: "JARX-REACH-001", Severity: finding.Medium, Title: "Credentials are readable without asking", Fix: "deny the paths"},
		finding.Rule{ID: "JARX-MCP-009", Severity: finding.Info, Title: "Points the agent at a credential file", Fix: "check why"},
		finding.Rule{ID: "JARX-VERSION-001", Severity: finding.High, Title: "Agent version has a known advisory", Fix: "update it"},
	)
	if err != nil {
		f.t.Fatal(err)
	}
	poison := f.finding("JARX-POISON-006", finding.High, model.AgentClaude, "/h/projects/tools/.mcp.json", `tool save_note: <script>alert(1)</script> token `+canaryToken)
	view := report.ScanView{
		Fake: true, Home: f.path("/h"), GOOS: "windows",
		Projects: []model.Project{
			{Path: f.path("/h/projects/tools"), Status: model.ProjectOK, Trust: []model.Trust{{Level: model.TrustTrusted, Origin: model.Origin{Agent: model.AgentClaude}}}},
			{Path: f.path("/h/projects/app"), Status: model.ProjectOK},
		},
		Findings: []finding.Finding{
			f.finding("JARX-MCP-009", finding.Info, model.AgentClaude, "/h/projects/tools/.mcp.json", "points at ~/.ssh"),
			poison,
			f.finding("JARX-REACH-001", finding.Medium, model.AgentCodex, "/h/projects/app", "codex: 8 credentials"),
			f.finding("JARX-VERSION-001", finding.High, model.AgentClaude, "/h/.local/bin/claude", "2.1.120, fixed in 2.1.204"),
		},
		Rules: rules,
		Since: time.Date(2026, 11, 25, 7, 14, 0, 0, time.UTC),
		Changes: []snapshot.Change{
			{Change: snapshot.Added, Item: snapshot.Item{Kind: snapshot.KindFinding, Key: f.text(snapshot.FindingKey(poison)), Value: f.text("high")}},
			{Change: snapshot.Removed, Item: snapshot.Item{Kind: snapshot.KindFinding, Key: f.text("JARX-PERMS-001 old"), Value: f.text("high")}},
			{Change: snapshot.Changed, Item: snapshot.Item{Kind: snapshot.KindInstruction, Key: f.text("claude CLAUDE.md")}, What: f.text("content changed")},
		},
	}
	arts := []llm.Artifact{
		{Kind: llm.KindSkill, Name: f.text("release"), Text: f.text("ship it"), Origin: model.Origin{File: f.path("/h/projects/app/.claude/skills/release/SKILL.md")}},
		{Kind: llm.KindTool, Name: f.text("save_note of notes"), Text: f.text("{}"), Origin: model.Origin{File: f.path("/h/projects/tools/.mcp.json")}},
	}
	return Data{
		Scan: view, Scanned: time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC), Version: "v1.2.3-test",
		StateDir: f.text(`/h/.jarx-state`), Repos: []redact.Text{f.text("/h/work/api")},
		LLM: LLM{On: true, BaseURL: f.text("https://llm.example.com/v1"), Model: f.text("m-1"), KeyEnv: f.text("JARX_LLM_KEY"), KeySet: false, Parallel: 4,
			Artifacts: arts, States: []llm.State{llm.StateNew, llm.StateFailed},
			Plan: llm.Preview{Send: 2, Failed: 1, New: 1, Tokens: 900, Host: "llm.example.com", ByKind: map[llm.Kind]int{llm.KindSkill: 1, llm.KindTool: 1}}},
	}
}

func get(t *testing.T, d Data, target string) (int, string, http.Header) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	rec := httptest.NewRecorder()
	Pages(func() Data { return d }).ServeHTTP(rec, req)
	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), resp.Header
}

// order says whether each want appears in body, in that order.
func order(body string, wants ...string) bool {
	at := 0
	for _, w := range wants {
		i := strings.Index(body[at:], w)
		if i < 0 {
			return false
		}
		at += i + len(w)
	}
	return true
}

func TestOverviewListsEveryFindingWorstFirst(t *testing.T) {
	code, body, _ := get(t, newFixture(t).data(), "/")

	if code != http.StatusOK {
		t.Fatalf("GET / = %d", code)
	}
	// Worst first, then by rule ID within a severity, like the CLI.
	if !order(body, "Tool text is aimed at the agent", "Agent version has a known advisory", "Credentials are readable without asking", "Points the agent at a credential file") {
		t.Errorf("findings aren't worst first:\n%s", body)
	}
}

func TestOverviewFilters(t *testing.T) {
	d := newFixture(t).data()
	all := []string{"Agent version has a known advisory", "Tool text is aimed at the agent", "Credentials are readable without asking", "Points the agent at a credential file"}
	for query, want := range map[string][]bool{
		"/?sev=high":             {true, true, false, false},
		"/?sev=high&sev=info":    {true, true, false, true},
		"/?project=1":            {false, false, true, false},
		"/?project=0&sev=info":   {false, false, false, true},
		"/?agent=codex":          {false, false, true, false},
		"/?area=POISON":          {false, true, false, false},
		"/?new=1":                {false, true, false, false},
		"/?project=user":         {true, false, false, false},
		"/?sev=med&agent=claude": {false, false, false, false},
	} {
		_, body, _ := get(t, d, query)
		at := strings.Index(body, `id="findings"`)
		if at < 0 {
			t.Fatalf("%s: no findings table", query)
		}
		table := body[at:]
		for i, title := range all {
			if strings.Contains(table, title) != want[i] {
				t.Errorf("%s: %q shown = %v, want %v", query, title, !want[i], want[i])
			}
		}
	}
}

func TestAFindingOpensInAModal(t *testing.T) {
	_, body, _ := get(t, newFixture(t).data(), "/")

	if strings.Contains(body, `<details class="finding"`) {
		t.Error("a finding still drops down in the table")
	}
	if !strings.Contains(body, `<button type="button" class="frow" data-open="f-0"`) {
		t.Error("the first row doesn't open its modal")
	}
	_, modal, found := strings.Cut(body, `<dialog class="modal" id="f-0"`)
	if !found {
		t.Fatal("no modal for the first finding")
	}
	modal, _, _ = strings.Cut(modal, "</dialog>")
	if !order(modal, "Tool text is aimed at the agent", `aria-label="Close"`, "Vulnerable line", "tool save_note", "Issue", "A tool description tells the agent what to do", "Recommendation", "Remove the server") {
		t.Errorf("the modal lacks the vulnerable line, issue or recommendation:\n%s", modal)
	}
	if !strings.Contains(body, `<span class="new">NEW</span>`) {
		t.Error("the finding added since the last scan isn't tagged NEW")
	}
}

func TestTheRowCutsLongEvidenceAndTheModalShowsItAll(t *testing.T) {
	f := newFixture(t)
	d := f.data()
	long := "deny Read(./.env) covers env_file " + strings.Repeat("abcdefghij", 12) + " END"
	d.Scan.Findings = append(d.Scan.Findings, f.finding("JARX-REACH-001", finding.Medium, model.AgentClaude, "/h/projects/app/x", long))

	_, body, _ := get(t, d, "/")

	short := []rune(long)[:72]
	if !strings.Contains(body, `<span class="ev mono">`+string(short)+`…</span>`) {
		t.Error("the row doesn't cut the evidence to 72 characters")
	}
	if !strings.Contains(body, long+"</pre>") {
		t.Error("the modal doesn't show the whole evidence")
	}
}

func TestPagesEscapeWhatFilesSayAndShowNoSecret(t *testing.T) {
	d := newFixture(t).data()
	for _, page := range []string{"/", "/projects/0", "/llm", "/changes", "/settings"} {
		_, body, _ := get(t, d, page)

		if strings.Contains(body, "<script>alert(1)</script>") {
			t.Errorf("%s: file text isn't escaped", page)
		}
		if strings.Contains(body, canaryToken) {
			t.Errorf("%s: shows the canary token", page)
		}
	}
	if _, body, _ := get(t, d, "/"); !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("the escaped evidence isn't on the overview")
	}
}

var (
	styleAttr    = regexp.MustCompile(`(?i)\sstyle\s*=`)
	inlineScript = regexp.MustCompile(`(?i)<script(\s[^>]*)?>\s*[^<\s]`)
	handlerAttr  = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	styleTag     = regexp.MustCompile(`(?i)<style`)
)

func TestPagesKeepToTheCSP(t *testing.T) {
	d := newFixture(t).data()
	for _, page := range []string{"/", "/?sev=high", "/projects/0", "/llm", "/changes", "/settings"} {
		code, body, _ := get(t, d, page)

		if code != http.StatusOK {
			t.Errorf("%s = %d", page, code)
		}
		for name, re := range map[string]*regexp.Regexp{"style attribute": styleAttr, "inline script": inlineScript, "handler attribute": handlerAttr, "style tag": styleTag} {
			if m := re.FindString(body); m != "" {
				t.Errorf("%s has a %s: %q", page, name, m)
			}
		}
		for _, s := range regexp.MustCompile(`(?i)<script[^>]*>`).FindAllString(body, -1) {
			if !strings.Contains(s, `src="/static/`) {
				t.Errorf("%s has a script that isn't the dashboard's own file: %q", page, s)
			}
		}
	}
}

func TestTheProjectPageShowsItsOwnFindings(t *testing.T) {
	d := newFixture(t).data()

	_, body, _ := get(t, d, "/projects/0")

	if !strings.Contains(body, "Tool text is aimed at the agent") || strings.Contains(body, "Credentials are readable without asking") {
		t.Errorf("project 0 shows another project's findings, or not its own")
	}
	if !strings.Contains(body, "claude trusted") {
		t.Error("the project page lacks claude's trust")
	}
	for _, bad := range []string{"/projects/9", "/projects/x", "/projects/-1"} {
		if code, _, _ := get(t, d, bad); code != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", bad, code)
		}
	}
}

func TestTheLLMPageIsAChecklist(t *testing.T) {
	_, body, _ := get(t, newFixture(t).data(), "/llm")

	for _, want := range []string{`type="checkbox"`, "release", "save_note of notes", "failed last time", "new", "llm.example.com", "m-1", "2 artifacts"} {
		if !strings.Contains(body, want) {
			t.Errorf("/llm lacks %q", want)
		}
	}
}

func TestTheLLMPageSaysHowToSetItUp(t *testing.T) {
	d := newFixture(t).data()
	d.LLM = LLM{}

	_, body, _ := get(t, d, "/llm")

	if !strings.Contains(body, "jarx setup llm") || strings.Contains(body, `type="checkbox"`) {
		t.Errorf("/llm when it's off = %q, want how to set it up and no checklist", body)
	}
}

func TestTheChangesPageListsWhatChanged(t *testing.T) {
	_, body, _ := get(t, newFixture(t).data(), "/changes")

	for _, want := range []string{"Previous scan", "2026-11-25", "07:14 UTC", "Added", "Removed", "Changed", "JARX-PERMS-001 old", "Content changed"} {
		if !strings.Contains(body, want) {
			t.Errorf("/changes lacks %q", want)
		}
	}
}

func TestTheSettingsPageShowsTheKeysVarNeverTheKey(t *testing.T) {
	_, body, _ := get(t, newFixture(t).data(), "/settings")

	for _, want := range []string{"https://llm.example.com/v1", "m-1", "JARX_LLM_KEY", "Not set", "<dt>Parallel requests</dt><dd>4</dd>", "~/work/api", "v1.2.3-test"} {
		if !strings.Contains(body, want) {
			t.Errorf("/settings lacks %q", want)
		}
	}
}

func TestStaticFilesAreServedWithTheirTypes(t *testing.T) {
	d := newFixture(t).data()
	for path, want := range map[string]string{
		"/static/app.css":     "text/css",
		"/static/app.js":      "text/javascript",
		"/static/theme.js":    "text/javascript",
		"/static/logo.svg":    "image/svg+xml",
		"/static/favicon.svg": "image/svg+xml",
		"/static/fonts/inter-latin-opsz-normal.woff2":      "font/woff2",
		"/static/fonts/geist-mono-latin-wght-normal.woff2": "font/woff2",
		"/static/fonts/geist-mono-OFL.txt":                 "text/plain",
	} {
		code, _, h := get(t, d, path)

		if code != http.StatusOK || !strings.HasPrefix(h.Get("Content-Type"), want) {
			t.Errorf("%s = %d %q, want 200 %s", path, code, h.Get("Content-Type"), want)
		}
	}
	if code, _, _ := get(t, d, "/static/../guard.go"); code == http.StatusOK {
		t.Error("static serves a file outside its folder")
	}
}

func TestUnknownPagesAre404(t *testing.T) {
	if code, _, _ := get(t, newFixture(t).data(), "/nope"); code != http.StatusNotFound {
		t.Errorf("/nope = %d, want 404", code)
	}
}

func TestTheSummaryCountsButDoesntFilter(t *testing.T) {
	_, body, _ := get(t, newFixture(t).data(), "/")

	at := strings.Index(body, `data-summary`)
	if at < 0 {
		t.Fatal("no summary on the overview")
	}
	summary := body[at:strings.Index(body, `id="findings"`)]
	for _, want := range []string{`<span class="big">4</span>`, "2 High", "1 Medium", "1 Info", "1 new", `href="/changes"`, "3 changed", "since 07:14 UTC", "2 projects"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary lacks %q", want)
		}
	}
	if strings.Contains(summary, "?sev=") {
		t.Error("the summary filters the table; only the toolbar should")
	}
}

func TestEachFacetIsItsOwnDropdown(t *testing.T) {
	_, body, _ := get(t, newFixture(t).data(), "/?sev=high&agent=claude")

	for _, want := range []string{
		`data-facet="sev"`, `data-facet="project"`, `data-facet="agent"`, `data-facet="area"`,
		"Severity: High", "Agent: Claude",
		`href="/?agent=claude"`,                             // clears severity, keeps agent
		`href="/?sev=high"`,                                 // clears agent, keeps severity
		`<input type="hidden" name="agent" value="claude">`, // the severity form keeps the agent filter
		"Clear all",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("toolbar lacks %q", want)
		}
	}
}

func TestProjectsShowTheirFolderNameWithTheFullPathOnHover(t *testing.T) {
	_, body, _ := get(t, newFixture(t).data(), "/")

	if !strings.Contains(body, `title="~/projects/tools"`) || !strings.Contains(body, `<span class="proj-name">tools</span>`) {
		t.Error("the sidebar doesn't show the folder name with the full path as its title")
	}
	if strings.Contains(body, `class="pbar"`) || strings.Contains(body, "worst first") {
		t.Error("the sidebar still has severity bars or the worst first label")
	}
}

func TestTheSidebarShowsSixProjectsThenViewAll(t *testing.T) {
	f := newFixture(t)
	d := f.data()
	for i := range 8 {
		d.Scan.Projects = append(d.Scan.Projects, model.Project{Path: f.path("/h/more/p" + string(rune('a'+i))), Status: model.ProjectOK})
	}

	_, body, _ := get(t, d, "/")

	before, _, found := strings.Cut(body, "View all 10")
	if !found {
		t.Fatal("no View all for 10 projects")
	}
	if n := strings.Count(before, `class="proj-link`); n != 6+1 { // six projects and the user config
		t.Errorf("%d project links before View all, want 6 and the user config", n)
	}
}

// manyFindings is the fixture with n more info findings in tools.
func manyFindings(t *testing.T, n int) Data {
	t.Helper()
	f := newFixture(t)
	d := f.data()
	for i := range n {
		d.Scan.Findings = append(d.Scan.Findings, f.finding("JARX-MCP-009", finding.Info, model.AgentClaude, "/h/projects/tools/f"+strconv.Itoa(i), "extra "+strconv.Itoa(i)))
	}
	return d
}

func TestFindingsArePaged(t *testing.T) {
	d := manyFindings(t, 41) // 45 in all

	_, first, _ := get(t, d, "/")
	_, third, _ := get(t, d, "/?page=3")
	_, wide, _ := get(t, d, "/?per=50")

	if n := strings.Count(first, `<div class="finding">`); n != 20 {
		t.Errorf("page 1 shows %d findings, want 20", n)
	}
	if n := strings.Count(third, `<div class="finding">`); n != 5 {
		t.Errorf("page 3 shows %d findings, want 5", n)
	}
	if n := strings.Count(wide, `<div class="finding">`); n != 45 {
		t.Errorf("50 per page shows %d findings, want 45", n)
	}
	for _, want := range []string{"Showing 1–20 of 45", `href="/?page=2"`, `href="/?page=3"`, `aria-current="page">1<`, `rel="next" href="/?page=2"`} {
		if !strings.Contains(first, want) {
			t.Errorf("page 1 lacks %q", want)
		}
	}
	if !strings.Contains(third, "Showing 41–45 of 45") || !strings.Contains(third, `rel="prev" href="/?page=2"`) {
		t.Error("page 3 lacks its range or the link back")
	}
	for _, per := range []string{`<option value="20" selected>`, `<option value="30">`, `<option value="50">`} {
		if !strings.Contains(first, per) {
			t.Errorf("rows per page lacks %q", per)
		}
	}
}

func TestPageLinksKeepTheFiltersAndSkipWithAnEllipsis(t *testing.T) {
	d := manyFindings(t, 200)

	_, body, _ := get(t, d, "/?sev=info&page=6")

	for _, want := range []string{`href="/?page=1&amp;sev=info"`, `href="/?page=5&amp;sev=info"`, `href="/?page=7&amp;sev=info"`, `href="/?page=11&amp;sev=info"`, `class="gap"`} {
		if !strings.Contains(body, want) {
			t.Errorf("pager lacks %q", want)
		}
	}
	if strings.Contains(body, `href="/?page=3&amp;sev=info"`) {
		t.Error("the pager lists every page instead of skipping with an ellipsis")
	}
	if _, past, _ := get(t, d, "/?page=999"); !strings.Contains(past, "Showing 201–201 of 201") && !strings.Contains(past, `aria-current="page">11<`) {
		t.Error("a page past the end doesn't go to the last page")
	}
}

func TestMachineInfoIsOnSettingsNotTheSidebar(t *testing.T) {
	d := newFixture(t).data()

	_, overview, _ := get(t, d, "/")
	_, settings, _ := get(t, d, "/settings")

	side, _, _ := strings.Cut(overview, "</aside>")
	if strings.Contains(side, "Fake home") || strings.Contains(side, "Scanned") {
		t.Error("the sidebar still shows the machine info")
	}
	for _, want := range []string{"Fake home · Windows", "Scanned"} {
		if !strings.Contains(settings, want) {
			t.Errorf("settings lacks %q", want)
		}
	}
}

func TestEveryPageHasTheThemeToggle(t *testing.T) {
	d := newFixture(t).data()
	for _, page := range []string{"/", "/projects/0", "/llm", "/changes", "/settings"} {
		_, body, _ := get(t, d, page)

		head, _, _ := strings.Cut(body, "</head>")
		if !strings.Contains(head, `<script src="/static/theme.js"></script>`) {
			t.Errorf("%s: the theme isn't set before the page paints", page)
		}
		if !strings.Contains(body, `data-theme-toggle`) {
			t.Errorf("%s: no theme toggle", page)
		}
	}
}

func TestViewAllCanBeCollapsedAgain(t *testing.T) {
	f := newFixture(t)
	d := f.data()
	for i := range 8 {
		d.Scan.Projects = append(d.Scan.Projects, model.Project{Path: f.path("/h/more/p" + string(rune('a'+i))), Status: model.ProjectOK})
	}

	_, body, _ := get(t, d, "/")

	if !strings.Contains(body, "View all 10") || !strings.Contains(body, "Show less") {
		t.Error("the project list can't be expanded and collapsed")
	}
}

func TestLiveSearchHasWhatItSwaps(t *testing.T) {
	_, body, _ := get(t, newFixture(t).data(), "/?q=tool")

	for _, want := range []string{`id="findings"`, `data-facets`, `data-search`, `value="tool"`} {
		if !strings.Contains(body, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
}

func TestTheThemeToggleSitsBySettings(t *testing.T) {
	_, body, _ := get(t, newFixture(t).data(), "/")

	side, _, _ := strings.Cut(body, "</aside>")
	_, foot, found := strings.Cut(side, `class="side-foot"`)
	if !found || !strings.Contains(foot, "data-theme-toggle") || !strings.Contains(foot, "Settings") {
		t.Error("the theme toggle isn't next to Settings")
	}
	if strings.Contains(body, `class="topbar"`) {
		t.Error("the theme toggle is still on top of the page")
	}
}

func TestTheNewCountSitsAfterTheLegend(t *testing.T) {
	_, body, _ := get(t, newFixture(t).data(), "/")

	_, summary, _ := strings.Cut(body, "data-summary")
	summary, _, _ = strings.Cut(summary, "</section>")
	if !order(summary, "1 Info", `class="legend-new"`, "1 new") {
		t.Errorf("the new count isn't after the legend:\n%s", summary)
	}
}

func TestPagesDontRepeatWhatJarxNeverDoes(t *testing.T) {
	d := newFixture(t).data()
	for _, page := range []string{"/", "/llm", "/changes", "/settings"} {
		_, body, _ := get(t, d, page)
		for _, line := range []string{"never stores", "only ever writes", "masked before", "127.0.0.1 only", "history never is"} {
			if strings.Contains(body, line) {
				t.Errorf("%s still says %q", page, line)
			}
		}
	}
}

func TestTheModalShowsWhereTheFindingIsAndCopiesItsPath(t *testing.T) {
	_, body, _ := get(t, newFixture(t).data(), "/")

	_, modal, _ := strings.Cut(body, `<dialog class="modal" id="f-0"`)
	modal, _, _ = strings.Cut(modal, "</dialog>")
	if !order(modal, "Tool text is aimed at the agent", "Vulnerable line", `class="rec"`, "Issue", "Recommendation", `class="modal-foot"`, "~/projects/tools", "claude · project scope") {
		t.Errorf("the modal lacks the line, the issue and recommendation box, or the footer's facts:\n%s", modal)
	}
	if strings.Contains(modal, `class="facts"`) {
		t.Error("agent, scope and project are still under the title")
	}
	if !strings.Contains(modal, `data-copy="/h/projects/tools/.mcp.json"`) || !strings.Contains(modal, "Copy path") {
		t.Error("the modal has no copy path button for the file")
	}
}

func TestAFindingLinkShowsJustThatFindingAndOpensIt(t *testing.T) {
	f := newFixture(t)
	d := f.data()
	poison := d.Scan.Findings[1]

	_, body, _ := get(t, d, "/?finding="+findingID(snapshot.FindingKey(poison)))

	if n := strings.Count(body, `<div class="finding">`); n != 1 {
		t.Errorf("the finding link shows %d findings, want 1", n)
	}
	if !strings.Contains(body, `data-autoopen`) || !strings.Contains(body, "Tool text is aimed at the agent") {
		t.Error("the linked finding doesn't open by itself")
	}
}

func TestViewFindingOpensItOnTheChangesPage(t *testing.T) {
	_, body, _ := get(t, newFixture(t).data(), "/changes")

	if !order(body, "Tool text is aimed at the agent", `data-open="c-0"`, "View finding") {
		t.Error("the new finding has no View finding button")
	}
	_, modal, found := strings.Cut(body, `<dialog class="modal" id="c-0"`)
	if !found {
		t.Fatal("the changes page has no modal for the new finding")
	}
	modal, _, _ = strings.Cut(modal, "</dialog>")
	if !order(modal, "Tool text is aimed at the agent", "Remove the server", "Open project") {
		t.Errorf("the modal on the changes page isn't the finding's:\n%s", modal)
	}
}

func TestEachChangeIsTaggedInOneList(t *testing.T) {
	_, body, _ := get(t, newFixture(t).data(), "/changes")

	if n := strings.Count(body, `<div class="crow">`); n != 3 {
		t.Errorf("%d change rows, want all 3 in one list", n)
	}
	for _, tag := range []string{`<span class="ctag ct-added">Added</span>`, `<span class="ctag ct-removed">Removed</span>`, `<span class="ctag ct-changed">Changed</span>`} {
		if !strings.Contains(body, tag) {
			t.Errorf("/changes lacks the tag %q", tag)
		}
	}
	if strings.Contains(body, "<h2>Added</h2>") {
		t.Error("changes are still split under subheadings")
	}
}

func TestTheSummaryBoxesFilterTheChanges(t *testing.T) {
	d := newFixture(t).data()

	_, all, _ := get(t, d, "/changes")
	_, removed, _ := get(t, d, "/changes?change=removed")

	for _, k := range []string{"added", "removed", "changed"} {
		if !strings.Contains(all, `href="/changes?change=`+k+`"`) {
			t.Errorf("the %s box isn't a filter", k)
		}
	}
	if strings.Contains(all, "Clear all") {
		t.Error("Clear all shows with no filter on")
	}
	if n := strings.Count(removed, `<div class="crow">`); n != 1 || !strings.Contains(removed, "JARX-PERMS-001 old") {
		t.Errorf("the removed filter shows %d rows, want just the removed one", n)
	}
	if !strings.Contains(removed, `aria-current="true"`) || !strings.Contains(removed, `href="/changes">Clear all</a>`) {
		t.Error("the removed filter isn't marked on, or there's no Clear all")
	}
}

func TestTheNewCountSaysIssues(t *testing.T) {
	_, body, _ := get(t, newFixture(t).data(), "/")

	if !strings.Contains(body, ">1 new issue</a>") {
		t.Error(`the summary doesn't say "1 new issue"`)
	}
}

func TestTheChangesPageHasTheScanHistory(t *testing.T) {
	d := newFixture(t).data()
	d.History = snapshot.RunLog{Total: 7, Runs: []snapshot.Run{
		{Taken: time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC), Findings: 4, NewFindings: 1, Added: 1, Removed: 1, Changed: 1},
		{Taken: time.Date(2026, 11, 25, 7, 14, 0, 0, time.UTC), Findings: 4, First: true},
	}}

	_, body, _ := get(t, d, "/changes")

	if !order(body, "Scan history", "7 scans", "2026-11-25 09:00 UTC", "1 new finding", "2026-11-25 07:14 UTC", "First scan") {
		t.Errorf("/changes lacks the scan history:\n%s", body)
	}
}

func TestARunSaysWhatChangedInPlainWords(t *testing.T) {
	for _, tc := range []struct {
		run  snapshot.Run
		want string
	}{
		{snapshot.Run{First: true}, "First scan"},
		{snapshot.Run{}, "No changes"},
		{snapshot.Run{Added: 4, Changed: 1}, "4 added · 1 changed"},
		{snapshot.Run{Added: 3, NewFindings: 1, Removed: 2}, "1 new finding · 2 other added · 2 removed"},
	} {
		if got := runSummary(tc.run); got != tc.want {
			t.Errorf("runSummary(%+v) = %q, want %q", tc.run, got, tc.want)
		}
	}
}

func TestTheScanHistoryShowsNewFindingsNotTotals(t *testing.T) {
	d := newFixture(t).data()
	d.History = snapshot.RunLog{Total: 2, Runs: []snapshot.Run{
		{Taken: time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC), Findings: 40, NewFindings: 3, Added: 3},
		{Taken: time.Date(2026, 11, 25, 7, 0, 0, 0, time.UTC), Findings: 37, First: true},
	}}

	_, body, _ := get(t, d, "/changes")

	_, hist, _ := strings.Cut(body, "Scan history")
	if !order(hist, "When", "New findings", "What changed", "2026-11-25 09:00 UTC", `<span class="hnew">3</span>`, "2026-11-25 07:00 UTC") {
		t.Errorf("the history lacks its new findings column:\n%s", hist)
	}
	for _, gone := range []string{"runbar", ">40<", ">37<", "Severity"} {
		if strings.Contains(hist, gone) {
			t.Errorf("the history still shows %q", gone)
		}
	}
}

func TestTheSidebarSaysUserConfigWithAnIconAndStaleInCaps(t *testing.T) {
	d := newFixture(t).data()
	d.Scan.Projects[1].Status = model.ProjectStale

	_, body, _ := get(t, d, "/")

	side, _, _ := strings.Cut(body, "</aside>")
	if strings.Contains(side, "your user config") || !strings.Contains(side, `<a class="proj-link user"`) || !strings.Contains(side, `<span class="proj-name">User config</span>`) {
		t.Error("the sidebar doesn't show user config, marked apart")
	}
	if !strings.Contains(side, `<span class="proj-status">stale</span>`) {
		t.Error("a stale project's status isn't a status tag")
	}
}

func TestTheModalFooterIsOneLine(t *testing.T) {
	_, body, _ := get(t, newFixture(t).data(), "/")

	_, modal, _ := strings.Cut(body, `<dialog class="modal" id="f-0"`)
	modal, _, _ = strings.Cut(modal, "</dialog>")
	if !order(modal, `<span class="foot-path`, "~/projects/tools", `<span class="dot">·</span>`, `<span class="foot-meta">claude · project scope</span>`) {
		t.Errorf("the footer isn't path · agent · scope:\n%s", modal)
	}
	if !strings.Contains(modal, "Remove the server.</p>") {
		t.Error("the recommendation doesn't read as a sentence")
	}
}

func TestTheProjectPageSaysHowFilesWereListed(t *testing.T) {
	d := newFixture(t).data()
	d.Scan.Projects[0].Walk = model.WalkGit

	_, body, _ := get(t, d, "/projects/0")

	if strings.Contains(body, "walked") || !strings.Contains(body, "Files from git") {
		t.Error(`the project page still says "walked", or doesn't say the files came from git`)
	}
}

func TestTheLLMPageKeepsToTheEssentials(t *testing.T) {
	_, body, _ := get(t, newFixture(t).data(), "/llm")

	for _, gone := range []string{"at a time", "checked ones go out", "Sending from the dashboard", `class="tile-foot"`, "never sent, or changed since"} {
		if strings.Contains(body, gone) {
			t.Errorf("/llm still shows %q", gone)
		}
	}
	if !strings.Contains(body, `<span class="dim">Skill</span>`) {
		t.Error("an artifact's kind doesn't start with a capital")
	}
}

func TestShortTextsStartWithACapital(t *testing.T) {
	d := newFixture(t).data()

	_, changes, _ := get(t, d, "/changes")
	_, settings, _ := get(t, d, "/settings")
	_, overview, _ := get(t, d, "/?agent=codex")

	for _, want := range []string{`<span class="faint">Instruction</span>`, `<span class="ev mono">Content changed</span>`} {
		if !strings.Contains(changes, want) {
			t.Errorf("/changes lacks %q", want)
		}
	}
	if !strings.Contains(settings, "Not set in the terminal that started jarx ui") {
		t.Error("the key's state doesn't start with a capital")
	}
	if !strings.Contains(overview, `<span class="cut">Codex</span>`) || !strings.Contains(overview, "Agent: Codex") {
		t.Error("the agent filter's options don't start with a capital")
	}
}

func TestAnInstructionFileIsNamedByItsFileName(t *testing.T) {
	f := newFixture(t)
	d := f.data()
	file := f.path("/h/projects/app/CLAUDE.md")
	d.LLM.Artifacts = append(d.LLM.Artifacts, llm.Artifact{Kind: llm.KindInstructions, Name: file.Text(), Text: f.text("be nice"), Origin: model.Origin{File: file}})

	_, body, _ := get(t, d, "/llm")

	if strings.Contains(body, `<span class="t">/h/projects/app/CLAUDE.md</span>`) || !strings.Contains(body, `<span class="t">CLAUDE.md</span>`) {
		t.Error("an instruction file is named by its whole path, not its file name")
	}
}
