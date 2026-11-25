package reach

import (
	"strconv"
	"strings"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
)

// ReadableSilently is credentials the agent can read without asking you.
func ReadableSilently() finding.Rule {
	return finding.Rule{
		ID: "JARX-REACH-001", Severity: finding.Medium, Title: "Credentials are readable without asking",
		Detail: "the agent can read these credentials with its file tools or the shell without asking you first, so a prompt injection can read them too",
		Fix:    "deny reads of them, turn on the sandbox with a denyRead or credentials.files entry, and set allowUnsandboxedCommands to false",
	}
}

// BypassableDeny is a deny or ask rule for a credential that the shell can
// get around.
func BypassableDeny() finding.Rule {
	return finding.Rule{
		ID: "JARX-REACH-002", Severity: finding.High, Title: "A credential's deny rule can be bypassed",
		Detail: "a deny rule for a credential doesn't really hold. For Claude, a Read deny only catches shell commands that name the file, like cat, and no sandbox backs it up. For Codex on native Windows, the unelevated sandbox doesn't support denied read paths.",
		Fix:    "Claude: turn on the sandbox with a denyRead or credentials.files entry, and set allowUnsandboxedCommands to false. Codex: pin windows.sandbox to mxc, or leave unelevated out of allowed_sandbox_implementations",
	}
}

// codexBypassable is one REACH-002 per Codex profile deny the unelevated
// Windows sandbox can get around, on the deny's own file.
func codexBypassable(s *redact.Scrubber, env platform.Env, p model.Project) []finding.Finding {
	x := newCodex(s, env, p, permissionsOf(p, model.AgentCodex))
	byRule := map[string][]string{}
	var order []model.PermissionRule
	for _, r := range p.Reach {
		if r.Agent != model.AgentCodex || r.Channel != model.ChannelShell || r.Verdict != model.ReachBypassable {
			continue
		}
		m, ok := x.profileMatch(model.Credential{Kind: r.Kind, Path: r.Path})
		if !ok || m.Action != model.RuleDeny {
			continue
		}
		key := m.Origin.File.Raw() + "\x00" + m.Rule.String()
		if _, had := byRule[key]; !had {
			order = append(order, m)
		}
		byRule[key] = append(byRule[key], label(r))
	}
	out := make([]finding.Finding, 0, len(order))
	for _, m := range order {
		key := m.Origin.File.Raw() + "\x00" + m.Rule.String()
		ev, _ := s.Scrub("deny " + m.Rule.String() + " covers " + strings.Join(byRule[key], ", ") + ", but " + x.denyUnenforced())
		out = append(out, BypassableDeny().New(m.Origin, ev))
	}
	return out
}

// Rules returns the analyzer's rules.
func Rules() []finding.Rule { return []finding.Rule{ReadableSilently(), BypassableDeny()} }

// maxNamed is how many credentials REACH-001's evidence names before the
// rest become a count.
const maxNamed = 4

// Analyze raises the findings from the verdicts Settle set.
func Analyze(s *redact.Scrubber, env platform.Env, projects []model.Project) []finding.Finding {
	var out []finding.Finding
	for _, p := range projects {
		if len(p.Reach) == 0 {
			continue
		}
		for _, a := range []model.Agent{model.AgentClaude, model.AgentCodex} {
			out = append(out, readable(s, p, a)...)
		}
		out = append(out, bypassable(s, env, p)...)
		out = append(out, codexBypassable(s, env, p)...)
	}
	return out
}

// label names a credential for evidence: its kind and path, or its name.
func label(r model.Reach) string {
	if r.Path.IsZero() {
		return string(r.Kind) + " " + r.Name.String()
	}
	return string(r.Kind) + " " + r.Path.Text().String()
}

// silentNames are the credentials an agent's file tools or shell read
// without asking, once each.
func silentNames(p model.Project, a model.Agent) []string {
	var names []string
	seen := map[string]bool{}
	for _, r := range p.Reach {
		if r.Agent != a || r.Channel != model.ChannelFileTools && r.Channel != model.ChannelShell {
			continue
		}
		if r.Verdict != model.ReachSilent && r.Verdict != model.ReachBypassable { // a bypassable deny reads silently too
			continue
		}
		if l := label(r); !seen[l] {
			seen[l] = true
			names = append(names, l)
		}
	}
	return names
}

// readable is one finding per project for the credentials the file tools
// or the shell read without asking.
func readable(s *redact.Scrubber, p model.Project, a model.Agent) []finding.Finding {
	names := silentNames(p, a)
	if len(names) == 0 {
		return nil
	}
	// No "credentials: x" here: that reads as NAME: value to the secret
	// masker, which would hide the first name.
	shown := names[:min(len(names), maxNamed)]
	list := strings.Join(shown, ", ")
	if rest := len(names) - len(shown); rest > 0 {
		list += " and " + strconv.Itoa(rest) + " more"
	}
	ev := string(a) + ": " + strconv.Itoa(len(names)) + " credentials (" + list + ")"
	if len(names) == 1 {
		ev = string(a) + ": 1 credential (" + names[0] + ")"
	}
	t, _ := s.Scrub(ev)
	o := model.Origin{Agent: a, File: p.Path, InEffect: true}
	return []finding.Finding{ReadableSilently().New(o, t)}
}

// bypassable is one finding per deny or ask rule that the shell gets
// around, on the rule's own file.
func bypassable(s *redact.Scrubber, env platform.Env, p model.Project) []finding.Finding {
	c := newClaude(s, env, p, permissionsOf(p, model.AgentClaude))
	byRule := map[string][]string{}
	var order []model.PermissionRule
	for _, r := range p.Reach {
		if r.Agent != model.AgentClaude || r.Channel != model.ChannelShell || r.Verdict != model.ReachBypassable {
			continue
		}
		cr := model.Credential{Kind: r.Kind, Path: r.Path}
		for _, action := range []model.RuleAction{model.RuleDeny, model.RuleAsk} {
			if rule, ok := c.fileRule(cr, action, "Read"); ok {
				key := rule.Origin.File.Raw() + "\x00" + rule.Rule.String()
				if _, had := byRule[key]; !had {
					order = append(order, rule)
				}
				byRule[key] = append(byRule[key], label(r))
				break
			}
		}
	}
	out := make([]finding.Finding, 0, len(order))
	for _, rule := range order {
		key := rule.Origin.File.Raw() + "\x00" + rule.Rule.String()
		ev, _ := s.Scrub(string(rule.Action) + " " + rule.Rule.String() + " covers " + strings.Join(byRule[key], ", ") + ", but Bash can read it with grep -r or a script: " + c.sandboxOff)
		out = append(out, BypassableDeny().New(rule.Origin, ev))
	}
	return out
}
