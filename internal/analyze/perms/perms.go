// Package perms works out what each agent may do in each project once
// every permission layer is merged, and flags the grants that hand over
// more than they look like.
package perms

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/nickelsec/jarx/internal/catalog"
	"github.com/nickelsec/jarx/internal/credmeta"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
)

func rule(id string, sev finding.Severity, title, fix string) finding.Rule {
	return finding.Rule{ID: id, Severity: sev, Title: title, Fix: fix}
}

func bypassMode() finding.Rule {
	return rule("JARX-PERMS-001", finding.High, "Claude starts in bypassPermissions, so it skips prompts and safety checks",
		"use a narrower default mode, or set permissions.disableBypassPermissionsMode")
}

func noSandbox() finding.Rule {
	return rule("JARX-PERMS-002", finding.High, "Codex runs with no sandbox",
		"use workspace-write or a permission profile, or run it inside a container you trust")
}

func neverAsk() finding.Rule {
	return rule("JARX-PERMS-003", finding.Medium, "Codex never asks for approval, so only the sandbox stands in the way",
		"use approval_policy = \"on-request\" for interactive work")
}

func everyCommand() finding.Rule {
	return rule("JARX-PERMS-004", finding.High, "an allow rule lets the agent run every command without a prompt",
		"allow the specific commands you need instead")
}

func credentialGrant() finding.Rule {
	return rule("JARX-PERMS-005", finding.High, "a grant covers credential files, so the agent can reach them without asking",
		"narrow the grant, or add deny rules for the credential paths")
}

func allProjectServers() finding.Rule {
	return rule("JARX-PERMS-006", finding.Medium, "every MCP server in the repo's .mcp.json starts without a prompt",
		"approve servers one by one instead of enableAllProjectMcpServers")
}

func retiredPolicy() finding.Rule {
	return rule("JARX-PERMS-007", finding.Info, "Codex's approval_policy is set to a value it no longer supports",
		"use on-request for interactive runs or never for non-interactive ones")
}

func runsAnything() finding.Rule {
	return rule("JARX-PERMS-008", finding.High, "an allow rule that looks narrow lets the agent run any code",
		"allow the exact commands instead of the interpreter or runner with any args")
}

func runsRepoCode() finding.Rule {
	return rule("JARX-PERMS-009", finding.Medium, "an allow rule runs code the repo defines, so whoever can push to it decides what runs",
		"keep the allow only for repos you trust, or approve these runs each time")
}

func hasEscape() finding.Rule {
	return rule("JARX-PERMS-010", finding.Medium, "an allow rule covers a tool that has a way to run any command",
		"allow the specific subcommands you need instead")
}

// codexOption flags one Codex option: its value in effect, and a retired
// approval policy in any layer, since Codex may refuse to start on one.
func (a *analysis) codexOption(o model.Option) {
	key := o.Key.String()
	if eff, ok := o.Setting.Effective(); ok {
		switch v := eff.Value.String(); {
		case key == "sandbox_mode" && v == "danger-full-access", key == "default_permissions" && v == ":danger-full-access":
			a.add(noSandbox(), eff.Origin, key+" = "+v+" in "+string(eff.Origin.Scope)+" config")
		case key == "approval_policy" && v == "never":
			a.add(neverAsk(), eff.Origin, "approval_policy = never in "+string(eff.Origin.Scope)+" config")
		}
	}
	if key == "approval_policy" {
		a.retired(o)
	}
}

// retired flags an approval policy Codex no longer supports, in any layer.
func (a *analysis) retired(o model.Option) {
	for _, l := range o.Setting.Layers {
		switch l.Value.String() {
		case "untrusted":
			a.add(retiredPolicy(), l.Origin, "approval_policy = untrusted is retired and can stop Codex from starting")
		case "on-failure":
			a.add(retiredPolicy(), l.Origin, "approval_policy = on-failure is deprecated")
		}
	}
}

// Rules is every rule this analyzer can raise.
func Rules() []finding.Rule {
	return []finding.Rule{
		bypassMode(), noSandbox(), neverAsk(), everyCommand(), credentialGrant(),
		allProjectServers(), retiredPolicy(), runsAnything(), runsRepoCode(), hasEscape(),
	}
}

// commandTool is a Claude tool whose rules name commands.
func commandTool(t string) bool { return t == "Bash" || t == "PowerShell" }

// fileTool is a Claude tool whose rules name paths it reads or writes.
func fileTool(t string) bool {
	switch t {
	case "Read", "Edit", "Write", "MultiEdit", "NotebookEdit":
		return true
	}
	return false
}

// ruleTool splits a Claude rule into its tool and pattern.
func ruleTool(rule string) (string, string) {
	inner, ok := strings.CutSuffix(rule, ")")
	if !ok {
		return rule, ""
	}
	if tool, pattern, ok := strings.Cut(inner, "("); ok {
		return tool, pattern
	}
	return rule, ""
}

func isSandboxRule(r model.PermissionRule) bool {
	return strings.HasPrefix(r.Rule.String(), "sandbox.")
}

// Settle marks Claude allow rules a deny or ask rule overrides. The
// permissions docs: rules are checked deny, then ask, then allow, and a
// tool denied at any level can't be allowed at another. A rule for the
// whole tool (Bash, or Bash(*)) covers every rule for it; otherwise only
// the same rule counts, since jarx can't tell how two patterns overlap.
func Settle(s *redact.Scrubber, projects []model.Project) {
	for pi := range projects {
		p := &projects[pi]
		for qi := range p.Permissions {
			perm := &p.Permissions[qi]
			if perm.Agent != model.AgentClaude {
				continue
			}
			for i := range perm.Rules {
				settleAllow(s, perm, i)
			}
		}
	}
}

func settleAllow(s *redact.Scrubber, perm *model.Permissions, i int) {
	a := &perm.Rules[i]
	if a.Action != model.RuleAllow || !a.Origin.InEffect || isSandboxRule(*a) {
		return
	}
	r, ok := shadow(perm.Rules, a.Rule.String())
	if !ok {
		return
	}
	why := "a deny rule for " + r.Rule.String() + " in " + r.Origin.File.Text().String() +
		" wins: Claude checks deny, then ask, then allow"
	if r.Action == model.RuleAsk {
		why = "an ask rule for " + r.Rule.String() + " in " + r.Origin.File.Text().String() + " wins, so Claude asks first"
	}
	a.Origin.InEffect = false
	a.Origin.Why, _ = s.Scrub(why)
}

// shadow finds the deny rule, or else the ask rule, in effect that covers
// allow: one for the whole tool, or the same rule.
func shadow(rules []model.PermissionRule, allow string) (model.PermissionRule, bool) {
	tool, pattern := ruleTool(allow)
	for _, action := range []model.RuleAction{model.RuleDeny, model.RuleAsk} {
		for _, r := range rules {
			if r.Action != action || !r.Origin.InEffect {
				continue
			}
			if t, p := ruleTool(r.Rule.String()); t == tool && (p == "" || p == "*" || p == pattern) {
				return r, true
			}
		}
	}
	return model.PermissionRule{}, false
}

// analysis collects findings for one scan, one per rule, file and grant.
type analysis struct {
	s    *redact.Scrubber
	env  platform.Env
	cmds []catalog.Command
	seen map[string]bool
	out  []finding.Finding
}

func (a *analysis) add(r finding.Rule, o model.Origin, evidence string) {
	key := r.ID + "\x00" + o.File.Raw() + "\x00" + evidence
	if a.seen[key] {
		return
	}
	a.seen[key] = true
	ev, _ := a.s.Scrub(evidence)
	a.out = append(a.out, r.New(o, ev))
}

// Analyze flags what's in effect in each project. Run Settle first.
func Analyze(s *redact.Scrubber, env platform.Env, projects []model.Project) ([]finding.Finding, error) {
	cmds, err := catalog.Commands()
	if err != nil {
		return nil, fmt.Errorf("loading the command table: %w", err)
	}
	a := &analysis{s: s, env: env, cmds: cmds, seen: map[string]bool{}}
	for _, p := range projects {
		samples := credmeta.Samples(env, p.Path.Raw())
		for _, perm := range p.Permissions {
			switch perm.Agent {
			case model.AgentClaude:
				a.claude(p, perm, samples)
			case model.AgentCodex:
				a.codex(p, perm, samples)
			case model.AgentJarx: // jarx's own records hold no permissions
			}
		}
		for _, sk := range p.Skills {
			if !sk.Origin.InEffect {
				continue
			}
			for _, t := range sk.Tools {
				a.allow(p, t.String(), sk.Origin, "skill "+sk.Name.String()+" pre-approves ", samples)
			}
		}
	}
	return a.out, nil
}

func (a *analysis) claude(p model.Project, perm model.Permissions, samples []credmeta.Sample) {
	if eff, ok := perm.DefaultMode.Effective(); ok && eff.Value.String() == "bypassPermissions" {
		a.add(bypassMode(), eff.Origin, "defaultMode is bypassPermissions in "+string(eff.Origin.Scope)+" settings")
	}
	a.claudeRules(p, perm, samples)
	for _, d := range perm.AdditionalDirectories {
		if d.Origin.InEffect {
			a.grant(pathMatcher(a.env, p.Path.Raw(), d.Value.String()), d.Origin, "additionalDirectories "+d.Value.String(), samples)
		}
	}
	a.claudeOptions(perm)
}

func (a *analysis) claudeRules(p model.Project, perm model.Permissions, samples []credmeta.Sample) {
	for _, r := range perm.Rules {
		if !r.Origin.InEffect {
			continue
		}
		switch {
		case isSandboxRule(r) && (r.Action == model.RuleRead || r.Action == model.RuleWrite):
			a.grant(pathMatcher(a.env, p.Path.Raw(), r.Target.String()), r.Origin, r.Rule.String(), samples)
		case r.Action == model.RuleAllow && !isSandboxRule(r):
			a.allow(p, r.Rule.String(), r.Origin, "", samples)
		}
	}
}

func (a *analysis) claudeOptions(perm model.Permissions) {
	for _, o := range perm.Options {
		if o.Key.String() != "enableAllProjectMcpServers" {
			continue
		}
		if eff, ok := o.Setting.Effective(); ok && eff.Value.String() == "true" {
			a.add(allProjectServers(), eff.Origin, "enableAllProjectMcpServers is true in "+string(eff.Origin.Scope)+" settings")
		}
	}
}

// allow checks one Claude allow rule, from settings or a skill.
func (a *analysis) allow(p model.Project, ruleText string, o model.Origin, prefix string, samples []credmeta.Sample) {
	tool, pattern := ruleTool(ruleText)
	switch {
	case commandTool(tool) && (pattern == "" || pattern == "*"):
		a.add(everyCommand(), o, prefix+ruleText)
	case commandTool(tool):
		switch class, why := classify(a.cmds, pattern); class {
		case catalog.RunsAnything:
			a.add(runsAnything(), o, prefix+ruleText+": "+why)
		case catalog.RunsRepoCode:
			a.add(runsRepoCode(), o, prefix+ruleText+": "+why)
		case catalog.HasEscape:
			a.add(hasEscape(), o, prefix+ruleText+": "+why)
		}
	case fileTool(tool):
		a.grant(claudeMatcher(a.env, p.Path.Raw(), o, pattern), o, prefix+ruleText, samples)
	}
}

// grant flags a grant that covers at least one credential sample.
func (a *analysis) grant(m matcher, o model.Origin, label string, samples []credmeta.Sample) {
	hits := covered(samples, m)
	if len(hits) == 0 {
		return
	}
	ev := label + " covers " + hits[0].Path + " (" + hits[0].Kind + ")"
	if n := len(hits) - 1; n > 0 {
		ev += " and " + strconv.Itoa(n) + " more credential file"
		if n > 1 {
			ev += "s"
		}
	}
	a.add(credentialGrant(), o, ev)
}

func (a *analysis) codex(p model.Project, perm model.Permissions, samples []credmeta.Sample) {
	for _, o := range perm.Options {
		a.codexOption(o)
	}
	for _, r := range perm.Rules {
		if r.Origin.InEffect && (r.Action == model.RuleRead || r.Action == model.RuleWrite) {
			a.grant(pathMatcher(a.env, p.Path.Raw(), r.Target.String()), r.Origin, r.Rule.String(), samples)
		}
	}
}
