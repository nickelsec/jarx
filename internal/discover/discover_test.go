package discover

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/agent/codex"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
)

func fakeContext(t *testing.T) agent.Context {
	t.Helper()
	env, err := platform.FromHome(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f, err := fsys.New(env)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	s, err := redact.New([]redact.Pattern{{Kind: "test_token", Re: regexp.MustCompile(`tok_[A-Za-z0-9]{16,}`)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return agent.Context{Env: env, Files: f, Scrub: s}
}

// fakeAdapter returns fixed projects, one per raw path.
type fakeAdapter struct {
	name     model.Agent
	paths    []string
	trust    model.TrustLevel
	findings []finding.Finding
}

func (a fakeAdapter) Agent() model.Agent { return a.name }

func (a fakeAdapter) Projects(c agent.Context) ([]model.Project, []finding.Finding) {
	out := make([]model.Project, 0, len(a.paths))
	for _, p := range a.paths {
		o := model.Origin{Agent: a.name, Scope: model.ScopeUser, InEffect: true}
		proj := model.Project{Path: model.NewPath(c.Scrub, p), Origins: []model.Origin{o}}
		if a.trust != "" {
			proj.Trust = []model.Trust{{Level: a.trust, Origin: o}}
		}
		out = append(out, proj)
	}
	return out, a.findings
}

func mkdir(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func byPath(ps []model.Project) map[string]model.Project {
	out := map[string]model.Project{}
	for _, p := range ps {
		out[p.Path.Raw()] = p
	}
	return out
}

func TestRunMergesTheSameProjectFromEveryAgent(t *testing.T) {
	c := fakeContext(t)
	app := mkdir(t, filepath.Join(c.Env.Home, "projects", "app"))

	r := Run(c, []agent.Adapter{
		fakeAdapter{name: model.AgentClaude, paths: []string{app}},
		fakeAdapter{name: model.AgentCodex, paths: []string{app + string(filepath.Separator)}, trust: model.TrustTrusted},
	}, nil)

	if len(r.Projects) != 1 {
		t.Fatalf("projects = %d, want the two records merged into 1", len(r.Projects))
	}
	p := r.Projects[0]
	if len(p.Origins) != 2 || p.Origins[0].Agent != model.AgentClaude || p.Origins[1].Agent != model.AgentCodex {
		t.Errorf("origins = %+v, want claude then codex", p.Origins)
	}
	if len(p.Trust) != 1 || p.Trust[0].Level != model.TrustTrusted {
		t.Errorf("trust = %+v, want codex's trusted", p.Trust)
	}
	if p.Status != model.ProjectOK {
		t.Errorf("status = %q, want ok", p.Status)
	}
}

func TestRunSetsEachProjectsStatus(t *testing.T) {
	c := fakeContext(t)
	ok := mkdir(t, filepath.Join(c.Env.Home, "ok"))
	file := filepath.Join(c.Env.Home, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()

	r := Run(c, []agent.Adapter{fakeAdapter{name: model.AgentClaude, paths: []string{
		ok, filepath.Join(c.Env.Home, "gone"), file, outside, "relative/path",
	}}}, nil)

	got := byPath(r.Projects)
	for path, want := range map[string]model.ProjectStatus{
		ok:                                model.ProjectOK,
		filepath.Join(c.Env.Home, "gone"): model.ProjectStale,
		file:                              model.ProjectStale,
		outside:                           model.ProjectOutsideHome,
		"relative/path":                   model.ProjectInvalid,
	} {
		if got[path].Status != want {
			t.Errorf("%s: status = %q, want %q", path, got[path].Status, want)
		}
	}
}

func TestRunAddsExtraPathsFromTheCommandLine(t *testing.T) {
	c := fakeContext(t)
	extra := mkdir(t, filepath.Join(c.Env.Home, "extra"))

	r := Run(c, nil, []string{extra})

	if len(r.Projects) != 1 || r.Projects[0].Path.Raw() != extra {
		t.Fatalf("projects = %+v, want the extra path", r.Projects)
	}
	o := r.Projects[0].Origins[0]
	if o.Agent != model.AgentJarx || o.Scope != model.ScopeCLI || r.Projects[0].Status != model.ProjectOK {
		t.Errorf("origin = %+v, status %q; want jarx, cli scope, ok", o, r.Projects[0].Status)
	}
}

func TestRunMakesRelativeExtraPathsAbsolute(t *testing.T) {
	c := fakeContext(t)
	mkdir(t, filepath.Join(c.Env.Home, "rel"))
	t.Chdir(c.Env.Home)

	r := Run(c, nil, []string{"rel"})

	if len(r.Projects) != 1 || r.Projects[0].Path.Raw() != filepath.Join(c.Env.Home, "rel") {
		t.Errorf("projects = %+v, want the absolute path", r.Projects)
	}
}

func TestRunSortsProjectsAndKeepsAdapterFindings(t *testing.T) {
	c := fakeContext(t)
	f := finding.UnreadableRecord().New(model.Origin{Agent: model.AgentCodex}, redact.Text{})

	r := Run(c, []agent.Adapter{
		fakeAdapter{name: model.AgentClaude, paths: []string{filepath.Join(c.Env.Home, "b"), filepath.Join(c.Env.Home, "a")}},
		fakeAdapter{name: model.AgentCodex, findings: []finding.Finding{f}},
	}, nil)

	if len(r.Projects) != 2 || r.Projects[0].Path.Raw() > r.Projects[1].Path.Raw() {
		t.Errorf("projects not sorted by path: %v", r.Projects)
	}
	if len(r.Findings) != 1 || r.Findings[0].RuleID != finding.UnreadableRecord().ID {
		t.Errorf("findings = %+v, want the adapter's finding", r.Findings)
	}
}

func TestRunReportsFilesFsysRefusedAsFindings(t *testing.T) {
	c := fakeContext(t)
	big := filepath.Join(c.Env.Home, ".codex", "config.toml")
	mkdir(t, filepath.Dir(big))
	if err := os.WriteFile(big, make([]byte, fsys.MaxReadSize+1), 0o600); err != nil {
		t.Fatal(err)
	}

	r := Run(c, []agent.Adapter{codex.Adapter{}}, nil)

	if len(r.Findings) != 1 || r.Findings[0].RuleID != finding.SkippedTooLarge().ID ||
		r.Findings[0].Origin.File.Raw() != big {
		t.Errorf("findings = %+v, want one %s for the oversized config", r.Findings, finding.SkippedTooLarge().ID)
	}
}
