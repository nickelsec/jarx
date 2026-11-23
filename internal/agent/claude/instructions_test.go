package claude

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
)

// instrView is an instruction with its path relative to the fake home.
type instrView struct {
	kind     model.InstructionKind
	path     string
	load     model.LoadWhen
	read     model.ReadStatus
	scope    model.Scope
	inEffect bool
}

func views(c agent.Context, is []model.Instruction) []instrView {
	out := make([]instrView, 0, len(is))
	for _, i := range is {
		rel, err := filepath.Rel(c.Env.Home, i.Path.Raw())
		if err != nil {
			rel = i.Path.Raw()
		}
		out = append(out, instrView{i.Kind, filepath.ToSlash(rel), i.Load, i.Read, i.Origin.Scope, i.Origin.InEffect})
	}
	return out
}

// instructionsFor runs the reader on one trusted ok project at /p, with the
// given walked files (relative to it).
func instructionsFor(t *testing.T, c agent.Context, walked ...string) (model.Project, []model.Instruction, []finding.Finding) {
	t.Helper()
	p := project(c, model.TrustTrusted)
	for _, w := range walked {
		p.Files = append(p.Files, model.NewPath(c.Scrub, w))
	}
	ps := []model.Project{p}
	global, fs := Adapter{}.Instructions(c, ps)
	return ps[0], global, fs
}

func find(t *testing.T, c agent.Context, is []model.Instruction, rel string) model.Instruction {
	t.Helper()
	for _, i := range is {
		if i.Path.Raw() == filepath.Join(c.Env.Home, filepath.FromSlash(rel)) {
			return i
		}
	}
	t.Fatalf("no instruction at %s in %+v", rel, views(c, is))
	return model.Instruction{}
}

func TestInstructionFilesLoadAtLaunch(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude/CLAUDE.md":   "user",
		"p/CLAUDE.md":         "project",
		"p/.claude/CLAUDE.md": "dot claude",
		"p/CLAUDE.local.md":   "local",
	})

	p, _, fs := instructionsFor(t, c)

	want := []instrView{
		{model.InstructionFile, ".claude/CLAUDE.md", model.LoadLaunch, model.ReadOK, model.ScopeUser, true},
		{model.InstructionFile, "p/CLAUDE.md", model.LoadLaunch, model.ReadOK, model.ScopeProject, true},
		{model.InstructionFile, "p/.claude/CLAUDE.md", model.LoadLaunch, model.ReadOK, model.ScopeProject, true},
		{model.InstructionLocal, "p/CLAUDE.local.md", model.LoadLaunch, model.ReadOK, model.ScopeLocal, true},
	}
	if got := views(c, p.Instructions); !slices.Equal(got, want) {
		t.Errorf("instructions =\n%+v\nwant\n%+v", got, want)
	}
	if got := find(t, c, p.Instructions, "p/CLAUDE.md").Text.String(); got != "project" {
		t.Errorf("text = %q, want the file", got)
	}
	if len(fs) != 0 {
		t.Errorf("findings = %+v, want none", fs)
	}
}

func TestParentFolderFilesLoadAtLaunchRootFirst(t *testing.T) {
	c := fakeHome(t, map[string]string{
		"CLAUDE.md":              "home level",
		"work/CLAUDE.md":         "parent",
		"work/CLAUDE.local.md":   "parent local",
		"work/p/CLAUDE.md":       "project",
		"work/sibling/CLAUDE.md": "not on the path",
	})
	p := model.Project{Path: model.NewPath(c.Scrub, c.Env.MapPath("/work/p")), Status: model.ProjectOK}
	ps := []model.Project{p}

	Adapter{}.Instructions(c, ps)

	got := make([]string, 0, len(ps[0].Instructions))
	for _, v := range views(c, ps[0].Instructions) {
		got = append(got, v.path)
	}
	if want := []string{"CLAUDE.md", "work/CLAUDE.md", "work/CLAUDE.local.md", "work/p/CLAUDE.md"}; !slices.Equal(got, want) {
		t.Errorf("paths = %q, want %q (root down, local after each dir's CLAUDE.md)", got, want)
	}
}

func TestSubfolderFilesLoadOnDemand(t *testing.T) {
	c := fakeHome(t, map[string]string{
		"p/CLAUDE.md":                  "top",
		"p/api/CLAUDE.md":              "api",
		"p/api/CLAUDE.local.md":        "api local",
		"p/web/.claude/rules/ui.md":    "nested rule",
		"p/node_modules/pkg/CLAUDE.md": "from a dependency",
	})

	p, _, _ := instructionsFor(t, c, "CLAUDE.md", "api/CLAUDE.md", "api/CLAUDE.local.md", "api/main.go",
		"web/.claude/rules/ui.md", "node_modules/pkg/CLAUDE.md")

	for rel, kind := range map[string]model.InstructionKind{
		"p/api/CLAUDE.md":              model.InstructionFile,
		"p/api/CLAUDE.local.md":        model.InstructionLocal,
		"p/web/.claude/rules/ui.md":    model.InstructionRule,
		"p/node_modules/pkg/CLAUDE.md": model.InstructionFile,
	} {
		i := find(t, c, p.Instructions, rel)
		if i.Kind != kind || i.Load != model.LoadOnDemand || !i.Origin.InEffect {
			t.Errorf("%s = %+v, want %s on demand", rel, views(c, []model.Instruction{i}), kind)
		}
	}
}

func TestRulesLoadAtLaunchOrWhenMatching(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude/rules/prefs.md":    "user rule",
		"p/.claude/rules/style.md":  "always",
		"p/.claude/rules/api/b.md":  "---\npaths:\n  - \"src/api/**/*.ts\"\n---\napi only",
		"p/.claude/rules/notes.txt": "not a rule",
		"p/.claude/rules/bad-fm.md": "---\npaths: [unclosed\nbody",
	})

	p, _, _ := instructionsFor(t, c)

	for rel, want := range map[string]struct {
		load  model.LoadWhen
		scope model.Scope
	}{
		".claude/rules/prefs.md":    {model.LoadLaunch, model.ScopeUser},
		"p/.claude/rules/style.md":  {model.LoadLaunch, model.ScopeProject},
		"p/.claude/rules/api/b.md":  {model.LoadMatching, model.ScopeProject},
		"p/.claude/rules/bad-fm.md": {model.LoadLaunch, model.ScopeProject}, // unparsed frontmatter: loads with no paths
	} {
		i := find(t, c, p.Instructions, rel)
		if i.Kind != model.InstructionRule || i.Load != want.load || i.Origin.Scope != want.scope {
			t.Errorf("%s = %+v, want a %s rule %s", rel, views(c, []model.Instruction{i}), want.scope, want.load)
		}
	}
	for _, i := range p.Instructions {
		if strings.HasSuffix(i.Path.Raw(), "notes.txt") {
			t.Errorf("notes.txt listed as an instruction, want only .md rules")
		}
	}
}

func TestAgentsMDLoadsOnlyWithoutClaudeMD(t *testing.T) {
	for name, tc := range map[string]struct {
		files map[string]string
		on    bool
	}{
		"alone":                        {map[string]string{"p/AGENTS.md": "a"}, true},
		"user CLAUDE.md doesn't count": {map[string]string{"p/AGENTS.md": "a", ".claude/CLAUDE.md": "u"}, true},
		"next to CLAUDE.md":            {map[string]string{"p/AGENTS.md": "a", "p/CLAUDE.md": "c"}, false},
		"next to CLAUDE.local.md":      {map[string]string{"p/AGENTS.md": "a", "p/CLAUDE.local.md": "l"}, false},
		"CLAUDE.md in a parent":        {map[string]string{"p/AGENTS.md": "a", "CLAUDE.md": "c"}, false},
		"both, by user setting": {map[string]string{"p/AGENTS.md": "a", "p/CLAUDE.md": "c",
			".claude/settings.json": `{"pluginConfigs": {"cc-plugin-agents-md@builtin": {"options": {"instructionFiles": "claude-md-and-agents-md"}}}}`}, true},
		"old plugin id": {map[string]string{"p/AGENTS.md": "a", "p/CLAUDE.md": "c",
			".claude/settings.json": `{"pluginConfigs": {"agents-md@builtin": {"options": {"instructionFiles": "claude-md-and-agents-md"}}}}`}, true},
		"setting ignored in project files": {map[string]string{"p/AGENTS.md": "a", "p/CLAUDE.md": "c",
			"p/.claude/settings.json": `{"pluginConfigs": {"cc-plugin-agents-md@builtin": {"options": {"instructionFiles": "claude-md-and-agents-md"}}}}`}, false},
		"claude-md only": {map[string]string{"p/AGENTS.md": "a",
			".claude/settings.json": `{"pluginConfigs": {"cc-plugin-agents-md@builtin": {"options": {"instructionFiles": "claude-md"}}}}`}, false},
	} {
		t.Run(name, func(t *testing.T) {
			c := fakeHome(t, tc.files)

			p, _, _ := instructionsFor(t, c)

			i := find(t, c, p.Instructions, "p/AGENTS.md")
			if i.Origin.InEffect != tc.on || (!tc.on && i.Origin.Why.IsZero()) {
				t.Errorf("AGENTS.md in effect = %v (why %q), want %v", i.Origin.InEffect, i.Origin.Why, tc.on)
			}
		})
	}
}

func TestManagedOnlyLeavesOutEverythingButManaged(t *testing.T) {
	c := managedHome(t,
		map[string]string{
			".claude/settings.json": `{"pluginConfigs": {"cc-plugin-agents-md@builtin": {"options": {"instructionFiles": "managed-only"}}}}`,
			".claude/CLAUDE.md":     "user",
			"p/CLAUDE.md":           "project",
			"p/.claude/rules/r.md":  "rule",
			"p/sub/CLAUDE.md":       "subdir",
		},
		map[string]string{"CLAUDE.md": "org"}, nil)

	p, _, _ := instructionsFor(t, c, "sub/CLAUDE.md")

	for _, i := range p.Instructions {
		rel, _ := filepath.Rel(c.Env.Home, i.Path.Raw())
		want := i.Origin.Scope == model.ScopeManaged || i.Load == model.LoadOnDemand
		if i.Origin.InEffect != want {
			t.Errorf("%s in effect = %v, want %v under managed-only", rel, i.Origin.InEffect, want)
		}
	}
}

func TestManagedInstructions(t *testing.T) {
	c := managedHome(t,
		map[string]string{".claude/settings.json": `{"claudeMd": "user claudeMd is ignored"}`},
		map[string]string{
			"CLAUDE.md":             "org file",
			"managed-settings.json": `{"claudeMd": "Always run make lint."}`,
		}, nil)

	p, _, _ := instructionsFor(t, c)

	var texts []string
	for _, i := range p.Instructions {
		if i.Origin.Scope == model.ScopeManaged && i.Origin.InEffect {
			texts = append(texts, string(i.Kind)+"="+i.Text.String())
		}
		if strings.Contains(i.Text.String(), "ignored") {
			t.Errorf("user claudeMd listed: %+v", views(c, []model.Instruction{i}))
		}
	}
	slices.Sort(texts)
	if want := []string{"instructions in settings=Always run make lint.", "instructions=org file"}; !slices.Equal(texts, want) {
		t.Errorf("managed = %q, want %q", texts, want)
	}
}

func TestImportsResolveFromTheImportingFile(t *testing.T) {
	c := fakeHome(t, map[string]string{
		"p/CLAUDE.md":       "See @docs/a.md and @/p/abs.md",
		"p/docs/a.md":       "then @b.md",
		"p/docs/b.md":       "leaf",
		"p/abs.md":          "absolute, read inside the fake home",
		".claude/CLAUDE.md": "mine: @~/notes/me.md",
		"notes/me.md":       "user import",
	})

	p, _, _ := instructionsFor(t, c)

	for rel, want := range map[string]struct {
		by    string
		depth int
		scope model.Scope
	}{
		"p/docs/a.md": {"p/CLAUDE.md", 1, model.ScopeProject},
		"p/docs/b.md": {"p/docs/a.md", 2, model.ScopeProject},
		"p/abs.md":    {"p/CLAUDE.md", 1, model.ScopeProject},
		"notes/me.md": {".claude/CLAUDE.md", 1, model.ScopeUser},
	} {
		i := find(t, c, p.Instructions, rel)
		by, _ := filepath.Rel(c.Env.Home, i.ImportedBy.Raw())
		if i.Kind != model.InstructionImport || filepath.ToSlash(by) != want.by || i.Depth != want.depth ||
			i.Origin.Scope != want.scope || !i.Origin.InEffect || i.Read != model.ReadOK {
			t.Errorf("%s = %+v by %s depth %d, want imported by %s at depth %d, in effect", rel,
				views(c, []model.Instruction{i}), by, i.Depth, want.by, want.depth)
		}
	}
}

func TestExternalImportsFromProjectFilesNeedApproval(t *testing.T) {
	c := fakeHome(t, map[string]string{
		"p/CLAUDE.md": "@../shared.md and @inside.md",
		"p/inside.md": "fine",
		"shared.md":   "outside the project",
	})

	p, _, _ := instructionsFor(t, c)

	if i := find(t, c, p.Instructions, "shared.md"); i.Origin.InEffect || !strings.Contains(i.Origin.Why.String(), "approv") {
		t.Errorf("external import = %+v why %q, want waiting on approval", views(c, []model.Instruction{i}), i.Origin.Why)
	}
	if i := find(t, c, p.Instructions, "p/inside.md"); !i.Origin.InEffect {
		t.Errorf("inside import not in effect: %q", i.Origin.Why)
	}
}

func TestImportsStopAtFourHops(t *testing.T) {
	files := map[string]string{"p/CLAUDE.md": "@h1.md"}
	for n := 1; n <= 5; n++ {
		files[fmt.Sprintf("p/h%d.md", n)] = fmt.Sprintf("@h%d.md", n+1)
	}
	files["p/h6.md"] = "never reached"
	c := fakeHome(t, files)

	p, _, _ := instructionsFor(t, c)

	for n := 1; n <= 4; n++ {
		if i := find(t, c, p.Instructions, fmt.Sprintf("p/h%d.md", n)); !i.Origin.InEffect || i.Read != model.ReadOK {
			t.Errorf("hop %d = %+v, want loaded", n, views(c, []model.Instruction{i}))
		}
	}
	five := find(t, c, p.Instructions, "p/h5.md")
	if five.Origin.InEffect || five.Read != model.ReadNotFollowed || !five.Text.IsZero() {
		t.Errorf("hop 5 = %+v, want listed, not read and not in effect", views(c, []model.Instruction{five}))
	}
	for _, i := range p.Instructions {
		if strings.HasSuffix(i.Path.Raw(), "h6.md") {
			t.Error("h6.md listed, want the walk to stop at the limit")
		}
	}
}

func TestImportCyclesAreListedOnce(t *testing.T) {
	c := fakeHome(t, map[string]string{
		"p/CLAUDE.md": "@a.md",
		"p/a.md":      "@b.md",
		"p/b.md":      "@a.md and @CLAUDE.md",
	})

	p, _, _ := instructionsFor(t, c)

	seen := map[string]int{}
	for _, v := range views(c, p.Instructions) {
		seen[v.path]++
	}
	for path, n := range seen {
		if n != 1 {
			t.Errorf("%s listed %d times, want once", path, n)
		}
	}
}

func TestMissingImportsAreListedNotLoaded(t *testing.T) {
	c := fakeHome(t, map[string]string{"p/CLAUDE.md": "@gone.md"})

	p, _, _ := instructionsFor(t, c)

	if i := find(t, c, p.Instructions, "p/gone.md"); i.Read != model.ReadMissing || i.Origin.InEffect {
		t.Errorf("missing import = %+v, want missing and not in effect", views(c, []model.Instruction{i}))
	}
}

func TestImportsOfCredentialFilesAreNeverRead(t *testing.T) {
	c := fakeHome(t, map[string]string{
		"p/CLAUDE.md":     "@.env and @~/.ssh/id_ed25519 and @linked.md",
		"p/.env":          "TOKEN=" + plainSecret,
		".ssh/id_ed25519": plainSecret,
	})

	p, _, fs := instructionsFor(t, c)

	for _, rel := range []string{"p/.env", ".ssh/id_ed25519"} {
		i := find(t, c, p.Instructions, rel)
		if i.Read != model.ReadCredential || !i.Text.IsZero() {
			t.Errorf("%s = %+v, want a credential, not read", rel, views(c, []model.Instruction{i}))
		}
		// jarx doesn't read it, but Claude loads it: that's the danger. (The
		// ~/.ssh one is outside the project, so it waits on approval.)
		if rel == "p/.env" && !i.Origin.InEffect {
			t.Errorf("%s not in effect (%q), want in effect: Claude still loads it", rel, i.Origin.Why)
		}
	}
	got := 0
	for _, f := range fs {
		if f.RuleID == ImportsCredential().ID {
			got++
		}
	}
	if got != 2 {
		t.Errorf("findings = %+v, want two %s", fs, ImportsCredential().ID)
	}
	if out := fmt.Sprintf("%+v %+v", p, fs); strings.Contains(out, plainSecret) {
		t.Errorf("a credential's content got into the output: %s", out)
	}
}

func TestSecretsInInstructionTextAreMasked(t *testing.T) {
	c := fakeHome(t, map[string]string{"p/CLAUDE.md": "use token " + canary})

	p, _, _ := instructionsFor(t, c)

	if got := find(t, c, p.Instructions, "p/CLAUDE.md").Text.String(); strings.Contains(got, canary) ||
		!strings.Contains(got, "REDACTED:test_token") {
		t.Errorf("text = %q, want the token masked", got)
	}
}

func TestImportsOfFilesNotLoadedAreNotLoadedEither(t *testing.T) {
	c := fakeHome(t, map[string]string{
		"p/CLAUDE.md":       "c",
		"p/AGENTS.md":       "@agents-extra.md",
		"p/agents-extra.md": "x",
	})

	p, _, _ := instructionsFor(t, c)

	if i := find(t, c, p.Instructions, "p/agents-extra.md"); i.Origin.InEffect {
		t.Errorf("import of an unloaded AGENTS.md is in effect, want not")
	}
}

func TestOutputStylesLoadWhenSelected(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude/settings.json":             `{"outputStyle": "Diagrams first"}`,
		".claude/output-styles/diagrams.md": "---\nname: Diagrams first\n---\nLead with a diagram.",
		"p/.claude/output-styles/terse.md":  "Be terse.",
	})

	p, _, _ := instructionsFor(t, c)

	if i := find(t, c, p.Instructions, ".claude/output-styles/diagrams.md"); i.Kind != model.InstructionOutputStyle ||
		i.Load != model.LoadSelected || !i.Origin.InEffect {
		t.Errorf("selected style = %+v, want in effect", views(c, []model.Instruction{i}))
	}
	if i := find(t, c, p.Instructions, "p/.claude/output-styles/terse.md"); i.Origin.InEffect || i.Origin.Why.IsZero() {
		t.Errorf("other style = %+v, want not in effect with a why", views(c, []model.Instruction{i}))
	}
}

func TestAutoMemoryWithoutAKnownFolderIsGlobal(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude/projects/some-folder/memory/MEMORY.md":    "- [role](user_role.md)",
		".claude/projects/some-folder/memory/user_role.md": "the user is a dev",
	})

	p, global, _ := instructionsFor(t, c)

	for _, i := range p.Instructions {
		if i.Kind == model.InstructionMemory {
			t.Errorf("memory tied to the project: %+v", views(c, []model.Instruction{i}))
		}
	}
	idx := find(t, c, global, ".claude/projects/some-folder/memory/MEMORY.md")
	topic := find(t, c, global, ".claude/projects/some-folder/memory/user_role.md")
	if idx.Load != model.LoadLaunch || topic.Load != model.LoadOnDemand || idx.Kind != model.InstructionMemory {
		t.Errorf("memory = %+v, want the index at launch and topics on demand", views(c, []model.Instruction{idx, topic}))
	}
}

func TestAutoMemoryDirectoryTiesMemoryToTheProject(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude/settings.json": `{"autoMemoryDirectory": "~/mem"}`,
		"mem/MEMORY.md":         "index",
	})

	p, _, _ := instructionsFor(t, c)

	if i := find(t, c, p.Instructions, "mem/MEMORY.md"); i.Kind != model.InstructionMemory || !i.Origin.InEffect {
		t.Errorf("memory = %+v, want the project's, in effect", views(c, []model.Instruction{i}))
	}
}

func TestAutoMemoryCanBeTurnedOff(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"setting": {".claude/settings.json": `{"autoMemoryEnabled": false, "autoMemoryDirectory": "~/mem"}`, "mem/MEMORY.md": "x"},
		"env var": {".jarx-env": "CLAUDE_CODE_DISABLE_AUTO_MEMORY=1\n", ".claude/settings.json": `{"autoMemoryDirectory": "~/mem"}`, "mem/MEMORY.md": "x"},
	} {
		t.Run(name, func(t *testing.T) {
			c := fakeHome(t, files)

			p, _, _ := instructionsFor(t, c)

			if i := find(t, c, p.Instructions, "mem/MEMORY.md"); i.Origin.InEffect || i.Origin.Why.IsZero() {
				t.Errorf("memory = %+v, want listed but off", views(c, []model.Instruction{i}))
			}
		})
	}
}

func TestAgentMemoryLoadsWhenItsSubagentRuns(t *testing.T) {
	c := fakeHome(t, map[string]string{
		"p/.claude/agent-memory/reviewer/MEMORY.md":       "project",
		"p/.claude/agent-memory-local/reviewer/MEMORY.md": "local",
		".claude/agent-memory/helper/MEMORY.md":           "user",
	})

	p, global, _ := instructionsFor(t, c)

	for rel, scope := range map[string]model.Scope{
		"p/.claude/agent-memory/reviewer/MEMORY.md":       model.ScopeProject,
		"p/.claude/agent-memory-local/reviewer/MEMORY.md": model.ScopeLocal,
	} {
		if i := find(t, c, p.Instructions, rel); i.Kind != model.InstructionAgentMemory || i.Load != model.LoadSubagent || i.Origin.Scope != scope {
			t.Errorf("%s = %+v, want %s agent memory", rel, views(c, []model.Instruction{i}), scope)
		}
	}
	if i := find(t, c, global, ".claude/agent-memory/helper/MEMORY.md"); i.Origin.Scope != model.ScopeUser {
		t.Errorf("user agent memory = %+v, want user scope", views(c, []model.Instruction{i}))
	}
}

func TestStaleProjectsHaveNoInstructions(t *testing.T) {
	c := fakeHome(t, map[string]string{"p/CLAUDE.md": "x"})
	ps := []model.Project{project(c, model.TrustTrusted)}
	ps[0].Status = model.ProjectStale

	Adapter{}.Instructions(c, ps)

	if len(ps[0].Instructions) != 0 {
		t.Errorf("instructions = %+v, want none", views(c, ps[0].Instructions))
	}
}
