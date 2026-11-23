package codex

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
)

func instructionsFor(t *testing.T, c agent.Context, dir string, trust model.TrustLevel) ([]model.Instruction, []finding.Finding) {
	t.Helper()
	p := model.Project{Path: model.NewPath(c.Scrub, c.Env.MapPath(dir)), Status: model.ProjectOK}
	if trust != "" {
		p.Trust = []model.Trust{{Level: trust, Origin: model.Origin{Agent: model.AgentCodex}}}
	}
	ps := []model.Project{p}
	_, fs := Adapter{}.Instructions(c, ps)
	return ps[0].Instructions, fs
}

// chain renders the instructions as path, with * when in effect.
func chain(c agent.Context, is []model.Instruction) []string {
	out := make([]string, 0, len(is))
	for _, i := range is {
		rel, _ := filepath.Rel(c.Env.Home, i.Path.Raw())
		s := filepath.ToSlash(rel)
		if i.Origin.InEffect {
			s += "*"
		}
		out = append(out, s)
	}
	return out
}

func findIn(t *testing.T, c agent.Context, is []model.Instruction, rel string) model.Instruction {
	t.Helper()
	for _, i := range is {
		if i.Path.Raw() == filepath.Join(c.Env.Home, filepath.FromSlash(rel)) {
			return i
		}
	}
	t.Fatalf("no instruction %s in %q", rel, chain(c, is))
	return model.Instruction{}
}

func TestGlobalOverrideWinsAndEmptyFilesAreSkipped(t *testing.T) {
	for name, tc := range map[string]struct {
		files map[string]string
		want  string
	}{
		"override wins": {map[string]string{".codex/AGENTS.override.md": "override", ".codex/AGENTS.md": "base"},
			".codex/AGENTS.override.md* .codex/AGENTS.md"},
		"empty override is skipped": {map[string]string{".codex/AGENTS.override.md": "", ".codex/AGENTS.md": "base"},
			".codex/AGENTS.override.md .codex/AGENTS.md*"},
	} {
		t.Run(name, func(t *testing.T) {
			c := fakeHome(t, tc.files)

			is, _ := instructionsFor(t, c, "/p", model.TrustTrusted)

			if got := strings.Join(chain(c, is), " "); got != tc.want {
				t.Errorf("chain = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestProjectChainRunsFromTheRootMarkerDownOneFilePerDir(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".codex/AGENTS.md":            "global",
		"mono/.git/HEAD":              "ref",
		"mono/AGENTS.md":              "root",
		"mono/pkg/AGENTS.override.md": "override",
		"mono/pkg/AGENTS.md":          "shadowed",
		"AGENTS.md":                   "above the root marker",
	})

	is, _ := instructionsFor(t, c, "/mono/pkg", model.TrustTrusted)

	want := ".codex/AGENTS.md* mono/AGENTS.md* mono/pkg/AGENTS.override.md* mono/pkg/AGENTS.md"
	if got := strings.Join(chain(c, is), " "); got != want {
		t.Errorf("chain = %s, want %s", got, want)
	}
	if why := findIn(t, c, is, "mono/pkg/AGENTS.md").Origin.Why.String(); !strings.Contains(why, "AGENTS.override.md") {
		t.Errorf("why = %q, want it to name the file that won the dir", why)
	}
}

func TestFallbackFilenamesComeAfterAgentsMD(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".codex/config.toml": `project_doc_fallback_filenames = ["TEAM_GUIDE.md"]`,
		"a/.git/HEAD":        "ref",
		"a/TEAM_GUIDE.md":    "team",
		"b/.git/HEAD":        "ref",
		"b/AGENTS.md":        "",
		"b/TEAM_GUIDE.md":    "team, since AGENTS.md is empty",
		"c/.git/HEAD":        "ref",
		"c/AGENTS.md":        "agents",
		"c/TEAM_GUIDE.md":    "loses",
	})

	for dir, want := range map[string]string{
		"/a": "a/TEAM_GUIDE.md*",
		"/b": "b/AGENTS.md b/TEAM_GUIDE.md*",
		"/c": "c/AGENTS.md* c/TEAM_GUIDE.md",
	} {
		is, _ := instructionsFor(t, c, dir, model.TrustTrusted)
		if got := strings.Join(chain(c, is), " "); got != want {
			t.Errorf("%s chain = %s, want %s", dir, got, want)
		}
	}
}

// capChain is a global file and two project files under a 10 byte cap: 8
// bytes, then 8 more (16 combined), then one that's over 10 on its own.
func capChain(t *testing.T) (agent.Context, []model.Instruction) {
	t.Helper()
	c := fakeHome(t, map[string]string{
		".codex/config.toml": "project_doc_max_bytes = 10",
		".codex/AGENTS.md":   "12345678",
		"m/.git/HEAD":        "ref",
		"m/AGENTS.md":        "abcdefgh",
		"m/sub/AGENTS.md":    "this one is long, " + canary,
	})
	is, _ := instructionsFor(t, c, "/m/sub", model.TrustTrusted)
	return c, is
}

func TestAFileUnderTheCapLoadsWhole(t *testing.T) {
	c, is := capChain(t)

	global := findIn(t, c, is, ".codex/AGENTS.md")
	if !global.Origin.InEffect || global.Limit != 0 || !global.Note.IsZero() {
		t.Errorf("global = in effect %v, limit %d, note %q; want all of it, no note", global.Origin.InEffect, global.Limit, global.Note)
	}
}

func TestTheCombinedReadingCutsAFileThatCrossesTheCap(t *testing.T) {
	c, is := capChain(t)

	root := findIn(t, c, is, "m/AGENTS.md")
	if !root.Origin.InEffect || root.Limit != 0 || !strings.Contains(root.Note.String(), "Codex cuts it after byte 2") {
		t.Errorf("root = in effect %v, limit %d, note %q; want all of it per file, cut under the combined reading", root.Origin.InEffect, root.Limit, root.Note)
	}
}

func TestAFilePastTheCapIsCutPerFileAndDroppedCombined(t *testing.T) {
	c, is := capChain(t)

	sub := findIn(t, c, is, "m/sub/AGENTS.md")
	note := sub.Note.String()
	if !sub.Origin.InEffect || sub.Limit != 10 {
		t.Errorf("sub = in effect %v, limit %d; want the first 10 bytes per file", sub.Origin.InEffect, sub.Limit)
	}
	if !strings.Contains(note, "earlier files already fill the cap, so Codex stops before this one") || strings.Contains(note, "cuts it after") {
		t.Errorf("sub note = %q, want past the combined cap", note)
	}
	if !strings.Contains(sub.Text.String(), "REDACTED:test_token") || strings.Contains(sub.Text.String(), canary) {
		t.Errorf("text = %q, want the whole file kept (past the cap too), with the token masked", sub.Text)
	}
}

func TestAZeroCapLoadsNothing(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".codex/config.toml": "project_doc_max_bytes = 0",
		".codex/AGENTS.md":   "global",
	})

	is, _ := instructionsFor(t, c, "/p", model.TrustTrusted)

	if g := findIn(t, c, is, ".codex/AGENTS.md"); g.Origin.InEffect {
		t.Errorf("global in effect with a zero cap, want not")
	}
}

func TestProjectAgentsMDWaitsForTrust(t *testing.T) {
	// Codex 0.150.0 changelog: untrusted projects no longer supply
	// project-level AGENTS.md instructions.
	for name, trust := range map[string]model.TrustLevel{"untrusted": model.TrustUntrusted, "no record": ""} {
		c := fakeHome(t, map[string]string{
			".codex/AGENTS.md": "my defaults",
			"p/.git/HEAD":      "ref",
			"p/AGENTS.md":      "repo guidance",
			"p/sub/AGENTS.md":  "more repo guidance",
		})

		is, _ := instructionsFor(t, c, "/p/sub", trust)

		for _, rel := range []string{"p/AGENTS.md", "p/sub/AGENTS.md"} {
			in := findIn(t, c, is, rel)
			if in.Origin.InEffect || !strings.Contains(in.Origin.Why.String(), "Codex 0.150.0") || in.Text.IsZero() {
				t.Errorf("%s: %s in effect = %v (%q), want not in effect with the version, and still read for the rules",
					name, rel, in.Origin.InEffect, in.Origin.Why)
			}
		}
		if g := findIn(t, c, is, ".codex/AGENTS.md"); !g.Origin.InEffect {
			t.Errorf("%s: global AGENTS.md not in effect (%q), want loaded: it isn't project-level", name, g.Origin.Why)
		}
	}
}

func TestTrustedProjectsLoadAgentsMD(t *testing.T) {
	c := fakeHome(t, map[string]string{"p/.git/HEAD": "ref", "p/AGENTS.md": "repo guidance"})

	is, _ := instructionsFor(t, c, "/p", model.TrustTrusted)

	if p := findIn(t, c, is, "p/AGENTS.md"); !p.Origin.InEffect {
		t.Errorf("AGENTS.md in a trusted project not in effect: %q", p.Origin.Why)
	}
}

func TestSkippedProjectFilesDontUseUpTheCap(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".codex/AGENTS.md":   "my defaults",
		".codex/config.toml": "project_doc_max_bytes = 20\n",
		"p/.git/HEAD":        "ref",
		"p/AGENTS.md":        strings.Repeat("x", 100),
	})

	is, _ := instructionsFor(t, c, "/p", model.TrustUntrusted)

	if g := findIn(t, c, is, ".codex/AGENTS.md"); g.Limit != 0 || !g.Note.IsZero() {
		t.Errorf("global limit %d, note %q; want none, the skipped project file isn't in the chain", g.Limit, g.Note)
	}
	if p := findIn(t, c, is, "p/AGENTS.md"); p.Limit != 0 || !p.Note.IsZero() {
		t.Errorf("skipped file limit %d, note %q; want no cap talk for a file Codex doesn't load", p.Limit, p.Note)
	}
}

func TestARepoChangingWhatInstructionsLoadIsAFinding(t *testing.T) {
	for name, tc := range map[string]struct {
		project string
		trust   model.TrustLevel
		want    int
	}{
		"lowers the cap":        {"project_doc_max_bytes = 100", model.TrustTrusted, 1},
		"adds fallback names":   {`project_doc_fallback_filenames = ["NOTES.md"]`, model.TrustTrusted, 1},
		"untrusted, not loaded": {"project_doc_max_bytes = 100", model.TrustUntrusted, 0},
		"something else":        {`approval_policy = "on-request"`, model.TrustTrusted, 0},
	} {
		t.Run(name, func(t *testing.T) {
			c := fakeHome(t, map[string]string{"p/.git/HEAD": "ref", "p/.codex/config.toml": tc.project})

			_, fs := instructionsFor(t, c, "/p", tc.trust)

			if got := ruleIDs(fs)[RepoChangesInstructions().ID]; got != tc.want {
				t.Errorf("%s findings = %d, want %d (%+v)", RepoChangesInstructions().ID, got, tc.want, fs)
			}
		})
	}
}

func TestAProjectCapAppliesOnlyWhenTrusted(t *testing.T) {
	c := fakeHome(t, map[string]string{
		"p/.git/HEAD":          "ref",
		"p/.codex/config.toml": "project_doc_max_bytes = 3",
		"p/AGENTS.md":          "longer than three bytes",
	})

	is, _ := instructionsFor(t, c, "/p", model.TrustUntrusted)

	if got := findIn(t, c, is, "p/AGENTS.md").Limit; got != 0 {
		t.Errorf("limit = %d, want 0: an untrusted project's config doesn't load", got)
	}
}

func TestTheCapCountsRawBytesNotMaskedText(t *testing.T) {
	// The token is 24 bytes, its mask "REDACTED:test_token" is 19. With a
	// 20 byte cap, Codex reads only part of the raw file.
	c := fakeHome(t, map[string]string{
		".codex/config.toml": "project_doc_max_bytes = 20",
		".codex/AGENTS.md":   canary,
	})

	is, _ := instructionsFor(t, c, "/p", model.TrustTrusted)

	if got := findIn(t, c, is, ".codex/AGENTS.md").Limit; got != 20 {
		t.Errorf("limit = %d, want 20: the raw file is over the cap", got)
	}
}

func TestInstructionsKeepWhatOtherAdaptersFound(t *testing.T) {
	c := fakeHome(t, map[string]string{".codex/AGENTS.md": "codex"})
	other := model.Instruction{Kind: model.InstructionFile, Origin: model.Origin{Agent: model.AgentClaude}}
	ps := []model.Project{{Path: model.NewPath(c.Scrub, c.Env.MapPath("/p")), Status: model.ProjectOK, Instructions: []model.Instruction{other}}}

	Adapter{}.Instructions(c, ps)

	if len(ps[0].Instructions) != 2 || ps[0].Instructions[0].Origin.Agent != model.AgentClaude {
		t.Errorf("instructions = %+v, want Claude's kept and Codex's added after", ps[0].Instructions)
	}
}

func TestYourOwnCapIsNotARepoFinding(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".codex/config.toml": "project_doc_max_bytes = 100\nproject_doc_fallback_filenames = [\"NOTES.md\"]\n",
		"p/.git/HEAD":        "ref",
	})

	_, fs := instructionsFor(t, c, "/p", model.TrustTrusted)

	if got := ruleIDs(fs)[RepoChangesInstructions().ID]; got != 0 {
		t.Errorf("%s findings = %d, want none: your own config choosing a cap is fine", RepoChangesInstructions().ID, got)
	}
}
