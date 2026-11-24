package discover

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/model"
)

// own is each agent's own dir in the fake home, where a session is the
// agent's internal work.
func own(c agent.Context) map[model.Agent]string {
	return map[model.Agent]string{model.AgentCodex: filepath.Join(c.Env.Home, ".codex")}
}

func rawPaths(ps []model.Project) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Path.Raw())
	}
	return out
}

func session(c agent.Context, a model.Agent, id, cwd string) model.Session {
	s := model.Session{Agent: a, ID: installText(c, id)}
	if cwd != "" {
		s.CWD = model.NewPath(c.Scrub, cwd)
	}
	return s
}

func TestASessionCwdIsAProjectTheAgentKnows(t *testing.T) {
	c := fakeContext(t)
	dir := mkdir(t, filepath.Join(c.Env.Home, "work", "app"))
	sessions := []model.Session{session(c, model.AgentClaude, "s1", dir)}

	res := Run(c, []agent.Adapter{History(own(c), sessions)}, nil)

	if len(res.Projects) != 1 || res.Projects[0].Path.Raw() != dir {
		t.Fatalf("projects = %q, want %s", rawPaths(res.Projects), dir)
	}
	o := res.Projects[0].Origins[0]
	if o.Agent != model.AgentClaude || o.Scope != model.ScopeHistory || !o.Observed {
		t.Errorf("origin = %s %s observed %v, want claude, history scope, observed", o.Agent, o.Scope, o.Observed)
	}
	if res.Projects[0].Status != model.ProjectOK {
		t.Errorf("status = %s, want ok: it's on disk", res.Projects[0].Status)
	}
}

func TestOneDirFromManySessionsIsOneProject(t *testing.T) {
	c := fakeContext(t)
	dir := mkdir(t, filepath.Join(c.Env.Home, "app"))
	sessions := []model.Session{
		session(c, model.AgentClaude, "s1", dir),
		session(c, model.AgentClaude, "s2", dir),
		session(c, model.AgentCodex, "t1", dir),
		session(c, model.AgentCodex, "t2", ""), // no cwd: no project
	}

	res := Run(c, []agent.Adapter{History(own(c), sessions)}, nil)

	if len(res.Projects) != 1 {
		t.Fatalf("projects = %q, want one", rawPaths(res.Projects))
	}
	agents := make([]string, 0, len(res.Projects[0].Origins))
	for _, o := range res.Projects[0].Origins {
		agents = append(agents, string(o.Agent))
	}
	slices.Sort(agents)
	if !slices.Equal(agents, []string{"claude", "codex"}) {
		t.Errorf("origins = %q, want one per agent", agents)
	}
}

func TestACodexCwdInsideCodexHomeIsntAProject(t *testing.T) {
	c := fakeContext(t)
	internal := mkdir(t, filepath.Join(c.Env.Home, ".codex", "worktrees", "x"))

	res := Run(c, []agent.Adapter{History(own(c), []model.Session{session(c, model.AgentCodex, "t1", internal)})}, nil)

	if len(res.Projects) != 0 {
		t.Errorf("projects = %q, want none: a rollout whose cwd is in CODEX_HOME is internal", rawPaths(res.Projects))
	}
}

func TestSessionsAttachToTheirProject(t *testing.T) {
	c := fakeContext(t)
	app := mkdir(t, filepath.Join(c.Env.Home, "app"))
	other := mkdir(t, filepath.Join(c.Env.Home, "other"))
	cased := app
	if c.Env.GOOS == "windows" {
		cased = strings.ToUpper(app[:1]) + app[1:] // a drive letter in the other case
	}
	sessions := []model.Session{session(c, model.AgentClaude, "s1", cased), session(c, model.AgentCodex, "t1", other)}
	projects := []model.Project{{Path: model.NewPath(c.Scrub, app)}, {Path: model.NewPath(c.Scrub, other)}}

	AttachSessions(c.Env.GOOS, projects, sessions)

	if len(projects[0].Sessions) != 1 || projects[0].Sessions[0].ID.String() != "s1" {
		t.Errorf("app sessions = %d, want s1", len(projects[0].Sessions))
	}
	if len(projects[1].Sessions) != 1 || projects[1].Sessions[0].ID.String() != "t1" {
		t.Errorf("other sessions = %d, want t1", len(projects[1].Sessions))
	}
}

func TestAGoneSessionCwdIsStale(t *testing.T) {
	c := fakeContext(t)
	gone := filepath.Join(c.Env.Home, "deleted")
	if err := os.RemoveAll(gone); err != nil {
		t.Fatal(err)
	}

	res := Run(c, []agent.Adapter{History(own(c), []model.Session{session(c, model.AgentClaude, "s1", gone)})}, nil)

	if len(res.Projects) != 1 || res.Projects[0].Status != model.ProjectStale {
		t.Errorf("projects = %q, want the gone dir as stale, like any recorded project", rawPaths(res.Projects))
	}
}
