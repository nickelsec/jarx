// Package discover finds every project the agents know about: the projects
// in each adapter's records plus extra paths from the command line, merged
// by path, each with a status.
package discover

import (
	"cmp"
	"errors"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/model"
)

// Result is what discover found.
type Result struct {
	Projects []model.Project
	Findings []finding.Finding
}

// Run asks every adapter for its projects, adds the extra paths, merges
// records of the same dir and sets each project's status. Files fsys refused
// to read show up as findings.
func Run(c agent.Context, adapters []agent.Adapter, extra []string) Result {
	var all []model.Project
	var findings []finding.Finding
	for _, a := range adapters {
		ps, fs := a.Projects(c)
		all = append(all, ps...)
		findings = append(findings, fs...)
	}
	for _, e := range extra {
		if abs, err := filepath.Abs(e); err == nil {
			e = abs
		}
		all = append(all, model.Project{
			Path:    model.NewPath(c.Scrub, e),
			Origins: []model.Origin{{Agent: model.AgentJarx, Scope: model.ScopeCLI, InEffect: true}},
		})
	}

	projects := merge(all, c.Env.GOOS)
	for i := range projects {
		projects[i].Status = status(c.Files, projects[i].Path.Raw())
	}
	findings = append(findings, finding.FromSkips(c.Scrub, c.Files.Skips())...)
	return Result{Projects: projects, Findings: findings}
}

// merge folds records of the same dir into one project, keeping every
// origin and trust in the order they came, and sorts by path.
func merge(all []model.Project, goos string) []model.Project {
	byKey := map[string]int{}
	var out []model.Project
	for _, p := range all {
		k := key(p.Path.Raw(), goos)
		if i, ok := byKey[k]; ok {
			out[i].Origins = append(out[i].Origins, p.Origins...)
			out[i].Trust = append(out[i].Trust, p.Trust...)
			continue
		}
		byKey[k] = len(out)
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b model.Project) int {
		return cmp.Compare(key(a.Path.Raw(), goos), key(b.Path.Raw(), goos))
	})
	return out
}

// key is how two records are matched as the same dir. Windows paths ignore
// case.
func key(p, goos string) string {
	k := filepath.Clean(p)
	if goos == "windows" {
		k = strings.ToLower(k)
	}
	return k
}

func status(files *fsys.FS, path string) model.ProjectStatus {
	if !filepath.IsAbs(path) {
		return model.ProjectInvalid
	}
	info, err := files.Stat(path)
	switch {
	case errors.Is(err, fsys.ErrOutsideHome):
		return model.ProjectOutsideHome
	case errors.Is(err, fs.ErrNotExist):
		return model.ProjectStale
	case err != nil:
		return model.ProjectUnreadable
	case !info.IsDir():
		return model.ProjectStale
	default:
		return model.ProjectOK
	}
}
