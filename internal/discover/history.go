package discover

import (
	"path/filepath"
	"strings"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
)

// History is a project source for the dirs the agents ran in: each
// distinct session cwd, one origin per agent (PRD, "Project discovery":
// session cwds). It's observed, not documented, like the history it comes
// from. A session inside an agent's own dir, like a Codex rollout whose
// cwd is in CODEX_HOME, is the agent's internal work, not a project.
func History(own map[model.Agent]string, sessions []model.Session) agent.Adapter {
	return history{own: own, sessions: sessions}
}

type history struct {
	own      map[model.Agent]string
	sessions []model.Session
}

func (history) Agent() model.Agent { return model.AgentJarx }

func (h history) Projects(c agent.Context) ([]model.Project, []finding.Finding) {
	seen := map[string]bool{}
	var out []model.Project
	for _, s := range h.sessions {
		cwd := s.CWD.Raw()
		if cwd == "" || !filepath.IsAbs(cwd) || within(c.Env.GOOS, cwd, h.own[s.Agent]) {
			continue
		}
		k := string(s.Agent) + "\x00" + key(cwd, c.Env.GOOS)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, model.Project{
			Path:    s.CWD,
			Origins: []model.Origin{{Agent: s.Agent, Scope: model.ScopeHistory, InEffect: true, Observed: true}},
		})
	}
	return out, nil
}

// within says whether path is dir or inside it.
func within(goos, path, dir string) bool {
	if dir == "" {
		return false
	}
	p, d := key(path, goos), key(dir, goos)
	return p == d || strings.HasPrefix(p, d+string(filepath.Separator))
}

// AttachSessions gives each project the sessions whose cwd is its dir,
// matched the way projects merge.
func AttachSessions(goos string, projects []model.Project, sessions []model.Session) {
	byKey := map[string]int{}
	for i := range projects {
		projects[i].Sessions = nil
		byKey[key(projects[i].Path.Raw(), goos)] = i
	}
	for _, s := range sessions {
		if i, ok := byKey[key(s.CWD.Raw(), goos)]; ok && !s.CWD.IsZero() {
			projects[i].Sessions = append(projects[i].Sessions, s)
		}
	}
}
