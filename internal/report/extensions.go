package report

import (
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/model"
)

// extensions lists a project's hooks, skills and plugins per agent.
func (p *Printer) extensions(proj model.Project) {
	root := proj.Path.Raw()
	for _, a := range agentsOf(proj) {
		p.hooks(a, root, proj.Hooks)
		p.skills(a, root, proj.Skills)
		p.plugins(a, proj.Plugins)
		p.servers(a, proj.Servers)
	}
}

// agentsOf lists the agents with any extensions in proj, in order.
func agentsOf(proj model.Project) []model.Agent {
	var out []model.Agent
	add := func(a model.Agent) {
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	for _, h := range proj.Hooks {
		add(h.Origin.Agent)
	}
	for _, s := range proj.Skills {
		add(s.Origin.Agent)
	}
	for _, pl := range proj.Plugins {
		add(pl.Origin.Agent)
	}
	for _, s := range proj.Servers {
		add(s.Origin.Agent)
	}
	return out
}

func notInEffect(o model.Origin) string {
	if o.InEffect {
		return ""
	}
	return "  not in effect: " + o.Why.String()
}

func (p *Printer) hooks(a model.Agent, root string, hs []model.Hook) {
	header := false
	for _, h := range hs {
		if h.Origin.Agent != a {
			continue
		}
		if !header {
			p.Out.Printf("    %s hooks\n", p.text(string(a)))
			header = true
		}
		event := h.Event.String()
		if !h.Matcher.IsZero() {
			event += " (" + h.Matcher.String() + ")"
		}
		detail := string(h.Origin.Scope)
		if !h.Script.IsZero() {
			detail += ", script " + relPath(root, h.Script)
			if h.ScriptRead != model.ReadOK {
				detail += " (" + string(h.ScriptRead) + ")"
			}
		}
		p.Out.Printf("      %s  %s  %s  %s\n", p.text(event), h.Type, h.Run, p.text(detail+notInEffect(h.Origin)+note(h.Note)))
	}
}

func (p *Printer) skills(a model.Agent, root string, ss []model.Skill) {
	header := false
	for _, s := range ss {
		if s.Origin.Agent != a {
			continue
		}
		if !header {
			p.Out.Printf("    %s skills\n", p.text(string(a)))
			header = true
		}
		p.Out.Printf("      %s  %s  %s  %s\n", p.text(string(s.Kind)), s.Name, p.shortPath(root, s.Path), p.text(skillDetail(s)))
	}
}

// skillDetail is a skill's scope, load time and what it grants or runs.
func skillDetail(s model.Skill) string {
	parts := []string{string(s.Origin.Scope), string(s.Load)}
	if !s.Plugin.IsZero() {
		parts = append(parts, "from "+s.Plugin.String())
	}
	if len(s.Tools) > 0 {
		names := make([]string, 0, len(s.Tools))
		for _, t := range s.Tools {
			names = append(names, t.String())
		}
		verb := "pre-approves "
		if s.Kind == model.SkillSubagent {
			verb = "tools "
		}
		parts = append(parts, verb+strings.Join(names, " "))
	}
	if !s.Mode.IsZero() {
		parts = append(parts, "mode "+s.Mode.String())
	}
	if !s.Hooks.IsZero() {
		parts = append(parts, "declares hooks")
	}
	if s.ShellCommands > 0 {
		parts = append(parts, "runs "+plural(s.ShellCommands, "shell command", "shell commands"))
	}
	if s.Read != model.ReadOK {
		parts = append(parts, string(s.Read))
	}
	return strings.Join(parts, ", ") + notInEffect(s.Origin)
}

func (p *Printer) plugins(a model.Agent, pls []model.Plugin) {
	header := false
	for _, pl := range pls {
		if pl.Origin.Agent != a {
			continue
		}
		if !header {
			p.Out.Printf("    %s plugins\n", p.text(string(a)))
			header = true
		}
		parts := []string{string(pl.Origin.Scope)}
		if !pl.Version.IsZero() {
			parts = append(parts, "version "+pl.Version.String())
		}
		if !pl.Path.IsZero() {
			parts = append(parts, pl.Path.Text().String())
		}
		if pl.Origin.Observed {
			parts = append(parts, "install record observed, not documented")
		}
		p.Out.Printf("      %s  %s\n", pl.ID, p.text(strings.Join(parts, ", ")+notInEffect(pl.Origin)))
	}
}

// servers lists a project's MCP server definitions: what each runs or
// where it connects, its scope and whether the agent would start it.
func (p *Printer) servers(a model.Agent, ss []model.Server) {
	header := false
	for _, s := range ss {
		if s.Origin.Agent != a {
			continue
		}
		if !header {
			p.Out.Printf("    %s MCP servers\n", p.text(string(a)))
			header = true
		}
		run := []string{s.URL.String()}
		if s.Transport == model.TransportStdio {
			run = []string{s.Command.String()}
			for _, arg := range s.Args {
				run = append(run, arg.String())
			}
		}
		parts := []string{string(s.Origin.Scope), string(s.Start)}
		if !s.Plugin.IsZero() {
			parts = append(parts, "from "+s.Plugin.String())
		}
		p.Out.Printf("      %s  %s  %s  %s\n", s.Name, p.text(string(s.Transport)), p.text(strings.Join(run, " ")),
			p.text(strings.Join(parts, ", ")+notInEffect(s.Origin)+note(s.Note)))
	}
}
