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
		Detail: "a Read deny or ask rule covers a credential, but it only catches shell commands that name the file, like cat; grep -r or a script that opens the file reads it anyway, and no sandbox backs the rule up",
		Fix:    "turn on the sandbox with a denyRead or credentials.files entry for it, and set allowUnsandboxedCommands to false",
	}
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
		out = append(out, readable(s, p)...)
		out = append(out, bypassable(s, env, p)...)
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

// readable is one finding per project for the credentials the file tools
// or the shell read without asking.
func readable(s *redact.Scrubber, p model.Project) []finding.Finding {
	var names []string
	seen := map[string]bool{}
	for _, r := range p.Reach {
		silent := r.Verdict == model.ReachSilent || r.Verdict == model.ReachBypassable // a bypassable deny reads silently too
		if !silent || (r.Channel != model.ChannelFileTools && r.Channel != model.ChannelShell) {
			continue
		}
		if l := label(r); !seen[l] {
			seen[l] = true
			names = append(names, l)
		}
	}
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
	ev := strconv.Itoa(len(names)) + " credentials (" + list + ")"
	if len(names) == 1 {
		ev = "1 credential (" + names[0] + ")"
	}
	t, _ := s.Scrub(ev)
	o := model.Origin{Agent: model.AgentClaude, File: p.Path, InEffect: true}
	return []finding.Finding{ReadableSilently().New(o, t)}
}

// bypassable is one finding per deny or ask rule that the shell gets
// around, on the rule's own file.
func bypassable(s *redact.Scrubber, env platform.Env, p model.Project) []finding.Finding {
	c := newClaude(s, env, p, permissionsOf(p, model.AgentClaude))
	byRule := map[string][]string{}
	var order []model.PermissionRule
	for _, r := range p.Reach {
		if r.Channel != model.ChannelShell || r.Verdict != model.ReachBypassable {
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
