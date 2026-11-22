// Package discover finds every project the agents know about: the projects
// in each adapter's records plus extra paths from the command line, merged
// by path, each with a status.
package discover

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/model"
)

const goosWindows = "windows"

// Result is what discover found.
type Result struct {
	Projects     []model.Project
	Unknown      []model.Unknown
	Instructions []model.Instruction // not tied to one project
	Findings     []finding.Finding
}

// Run asks every adapter for its projects, adds the extra paths, merges
// records of the same dir and sets each project's status. Then every adapter
// that reads settings or instructions reads them for the ok projects. Files
// fsys refused to read show up as findings, so this comes last.
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
		p := &projects[i]
		p.Status = status(c.Files, p.Path.Raw())
		if p.Status == model.ProjectOK {
			findings = append(findings, walkProject(c, p, maxFiles)...)
		}
	}
	var unknown []model.Unknown
	var global []model.Instruction
	for _, a := range adapters {
		if sr, ok := a.(agent.SettingsReader); ok {
			u, fs := sr.Settings(c, projects)
			unknown = append(unknown, u...)
			findings = append(findings, fs...)
		}
		if ir, ok := a.(agent.InstructionReader); ok {
			is, fs := ir.Instructions(c, projects)
			global = append(global, is...)
			findings = append(findings, fs...)
		}
	}
	findings = append(findings, finding.FromSkips(c.Scrub, c.Files.Skips())...)
	return Result{Projects: projects, Unknown: unknown, Instructions: global, Findings: findings}
}

// walkProject lists p's files. A walk cut off at limit is a finding, so it's
// never silent.
func walkProject(c agent.Context, p *model.Project, limit int) []finding.Finding {
	w := walkRepo(context.Background(), c, p.Path.Raw(), limit)
	p.Walk = w.method
	for _, f := range w.files {
		p.Files = append(p.Files, model.NewPath(c.Scrub, f))
	}
	if !w.truncated {
		return nil
	}
	ev, _ := c.Scrub.Scrub(fmt.Sprintf("listed the first %d files", limit))
	origin := model.Origin{Agent: model.AgentJarx, File: p.Path, InEffect: true}
	return []finding.Finding{finding.WalkTruncated().New(origin, ev)}
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
	if goos == goosWindows {
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

// Saved returns an adapter for the repos saved with jarx setup repo add.
// configFile is where they're saved, for the origin.
func Saved(configFile string, repos []string) agent.Adapter {
	return saved{configFile: configFile, repos: repos}
}

type saved struct {
	configFile string
	repos      []string
}

func (saved) Agent() model.Agent { return model.AgentJarx }

func (s saved) Projects(c agent.Context) ([]model.Project, []finding.Finding) {
	origin := model.Origin{
		Agent:    model.AgentJarx,
		File:     model.NewPath(c.Scrub, s.configFile),
		Scope:    model.ScopeJarx,
		InEffect: true,
	}
	out := make([]model.Project, 0, len(s.repos))
	for _, r := range s.repos {
		out = append(out, model.Project{Path: model.NewPath(c.Scrub, r), Origins: []model.Origin{origin}})
	}
	return out, nil
}
