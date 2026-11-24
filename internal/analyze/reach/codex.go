package reach

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/analyze/perms"
	"github.com/nickelsec/jarx/internal/credmeta"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
)

// codex is what decides a Codex verdict in one project. From the Codex
// docs (permissions, agent approvals and security, config reference):
// the sandbox modes and built-in profiles limit writes, not reads; a custom
// profile reads only what it grants, unless it extends a built-in; a
// profile deny blocks reads and wins an equally specific grant; and a
// blocked command can ask to run outside the sandbox, which the approval
// policy decides.
type codex struct {
	s    *redact.Scrubber
	env  platform.Env
	p    model.Project
	perm model.Permissions

	legacy, legacyFile   string // sandbox_mode in effect, and its file
	profile, profileFile string // default_permissions in effect, and its file
	extends              string // the profile's extends, when it has one
}

func newCodex(s *redact.Scrubber, env platform.Env, p model.Project, perm model.Permissions) *codex {
	x := &codex{s: s, env: env, p: p, perm: perm}
	x.legacy, x.legacyFile = x.option("sandbox_mode")
	if x.legacy == "" {
		x.profile, x.profileFile = x.option("default_permissions")
	}
	if x.profile != "" && !builtin(x.profile) {
		x.extends, _ = x.option("permissions." + x.profile + ".extends")
	}
	return x
}

func builtin(profile string) bool { return strings.HasPrefix(profile, ":") }

func (x *codex) text(v string) redact.Text {
	t, _ := x.s.Scrub(v)
	return t
}

func (x *codex) texts(vs ...string) []redact.Text {
	out := make([]redact.Text, 0, len(vs))
	for _, v := range vs {
		if v != "" {
			out = append(out, x.text(v))
		}
	}
	return out
}

func (x *codex) option(key string) (string, string) {
	for _, o := range x.perm.Options {
		if o.Key.String() != key {
			continue
		}
		if eff, ok := o.Setting.Effective(); ok {
			return eff.Value.String(), eff.Origin.File.Text().String()
		}
	}
	return "", ""
}

func (x *codex) verdicts(cr model.Credential) []model.Reach {
	pc := process{s: x.s, p: x.p, agent: model.AgentCodex, strips: func(string) bool { return false }}
	if cr.Kind == credmeta.KindEnvVar {
		return append([]model.Reach{x.envShell(cr)}, pc.channels(cr, true)...)
	}
	return append([]model.Reach{x.shell(cr)}, pc.channels(cr, false)...)
}

// codexPath matches a profile's filesystem key: :root is everything,
// :workspace_roots (and its subpaths) is the project, the other tokens are
// runtime paths that hold no credentials, and the rest are ~ or absolute
// paths and globs.
func (x *codex) codexPath(key string) func(string) bool {
	switch {
	case key == ":root":
		return func(string) bool { return true }
	case key == ":workspace_roots" || strings.HasPrefix(key, ":workspace_roots/"):
		sub := strings.TrimPrefix(strings.TrimPrefix(key, ":workspace_roots"), "/")
		if sub == "" || sub == "." {
			sub = ""
		}
		return perms.SandboxPath(x.env, x.p.Path.Raw(), model.Origin{Scope: model.ScopeProject}, filepath.Join(x.p.Path.Raw(), sub))
	case strings.HasPrefix(key, ":"):
		return func(string) bool { return false }
	}
	return perms.SandboxPath(x.env, x.p.Path.Raw(), model.Origin{Scope: model.ScopeUser}, key)
}

// profileMatch is the most specific in-effect profile entry that covers
// the credential, and whether it denies. A deny wins an equally specific
// grant.
func (x *codex) profileMatch(cr model.Credential) (model.PermissionRule, bool) {
	var best model.PermissionRule
	n := -1
	found := false
	for _, r := range x.perm.Rules {
		if !r.Origin.InEffect || !strings.HasPrefix(r.Rule.String(), x.profile+" ") {
			continue
		}
		t := r.Target.String()
		if !covers(x.codexPath(t), cr) {
			continue
		}
		if len(t) > n || len(t) == n && r.Action == model.RuleDeny {
			best, n, found = r, len(t), true
		}
	}
	return best, found
}

// droppedDeny is a profile deny Codex ignores because sandbox_mode is set.
func (x *codex) droppedDeny(cr model.Credential) string {
	for _, r := range x.perm.Rules {
		if r.Action == model.RuleDeny && !r.Origin.InEffect && strings.Contains(r.Origin.Why.String(), "ignores permission profiles") &&
			covers(x.codexPath(r.Target.String()), cr) {
			return "the profile's deny " + r.Rule.String() + " would cover it, but " + r.Origin.Why.String()
		}
	}
	return ""
}

// shell is shell commands and apply_patch, Codex's way to files.
func (x *codex) shell(cr model.Credential) model.Reach {
	r := reachOf(model.AgentCodex, cr, model.ChannelShell)
	switch {
	case x.legacy == "danger-full-access":
		r.Verdict, r.Why = model.ReachSilent, x.texts("sandbox_mode is danger-full-access in "+x.legacyFile+", so there's no sandbox")
	case x.legacy != "":
		r.Verdict, r.Why = model.ReachSilent, x.texts("sandbox_mode "+x.legacy+" in "+x.legacyFile+" limits writes, not reads", x.droppedDeny(cr))
	case x.profile == ":danger-full-access":
		r.Verdict, r.Why = model.ReachSilent, x.texts("default_permissions is :danger-full-access in "+x.profileFile+", so there's no sandbox")
	case x.profile == "":
		r.Verdict, r.Why = model.ReachSilent, x.texts("no sandbox_mode or default_permissions is set, and Codex's default sandbox limits writes, not reads")
	case builtin(x.profile):
		r.Verdict, r.Why = model.ReachSilent, x.texts("the built-in profile "+x.profile+" in "+x.profileFile+" limits writes, not reads")
	default:
		return x.custom(r, cr)
	}
	return r
}

// custom is a credential under a profile the user defined.
func (x *codex) custom(r model.Reach, cr model.Credential) model.Reach {
	m, ok := x.profileMatch(cr)
	switch {
	case ok && m.Action == model.RuleDeny:
		denies := "profile " + x.profile + " denies it: " + m.Rule.String() + " in " + m.Origin.File.Text().String()
		if why := x.denyUnenforced(); why != "" {
			r.Verdict, r.Why = model.ReachBypassable, x.texts(denies, why)
			return r
		}
		r = x.escalate(r, denies)
		if strings.ContainsAny(m.Target.String(), "*?") {
			r.Why = append(r.Why, x.text("a glob deny is matched when each sandboxed process starts, so a matching file created later stays readable to a process already running"))
		}
		return r
	case ok:
		r.Verdict, r.Why = model.ReachSilent, x.texts("profile "+x.profile+" grants "+m.Rule.String()+" in "+m.Origin.File.Text().String())
		return r
	case x.extends != "":
		r.Verdict, r.Why = model.ReachSilent, x.texts("profile "+x.profile+" extends "+x.extends+", whose reads aren't limited")
		return r
	}
	return x.escalate(r, "profile "+x.profile+" in "+x.profileFile+" doesn't grant it, and doesn't extend a built-in")
}

// denyUnenforced says why a profile deny may not block reads, or "". On
// native Windows the unelevated sandbox doesn't support denied read paths,
// and Codex falls back to it when elevated setup isn't available (Windows
// sandbox docs). Only a pinned, allowed mxc, or requirements that leave
// unelevated out, rule it out; jarx can't see which one the device picks.
func (x *codex) denyUnenforced() string {
	if x.env.GOOS != goosWindows {
		return ""
	}
	sb, _ := x.option("windows.sandbox")
	mxc, _ := x.option("windows.allow_mxc")
	impls, _ := x.option("windows.allowed_sandbox_implementations")
	switch {
	case sb == "mxc" && mxc != valueFalse:
		return ""
	case impls != "" && !slices.Contains(strings.Split(strings.ReplaceAll(impls, " ", ""), ","), "unelevated"):
		return ""
	}
	return "on native Windows the unelevated sandbox doesn't support denied read paths, and Codex falls back to it when elevated setup isn't available; nothing here rules it out"
}

// goosWindows is native Windows.
const goosWindows = "windows"

// escalate is what happens once the sandbox stops a read: Codex can ask to
// run the command outside the sandbox, which approval_policy decides. An
// unset approval_policy counts as on-request, the interactive default.
func (x *codex) escalate(r model.Reach, blockedBy string) model.Reach {
	policy, pf := x.option("approval_policy")
	sa, sf := x.option("approval_policy.granular.sandbox_approval")
	reviewer, rf := x.option("approvals_reviewer")
	switch {
	case policy == "never":
		r.Verdict, r.Why = model.ReachBlocked, x.texts(blockedBy, "approval_policy is never in "+pf+", so Codex can't ask to leave the sandbox")
	case sa == valueFalse:
		r.Verdict, r.Why = model.ReachBlocked, x.texts(blockedBy, "granular sandbox_approval is false in "+sf+", which auto-rejects leaving the sandbox")
	case reviewer == "auto_review":
		r.Verdict, r.Why = model.ReachSilent, x.texts(blockedBy, "approvals_reviewer is auto_review in "+rf+": a reviewer subagent approves leaving the sandbox instead of you")
	default:
		why := "approval_policy isn't set, which counts as on-request: Codex asks you to leave the sandbox"
		if policy != "" {
			why = "approval_policy " + policy + " in " + pf + ": Codex asks you to leave the sandbox"
		}
		r.Verdict, r.Why = model.ReachApproval, x.texts(blockedBy, why)
	}
	return r
}

// secretWords are the names the default excludes drop, when they're on.
var secretWords = regexp.MustCompile(`(?i)KEY|SECRET|TOKEN`)

// envShell is an env var through commands, after shell_environment_policy.
func (x *codex) envShell(cr model.Credential) model.Reach {
	r := reachOf(model.AgentCodex, cr, model.ChannelShell)
	name := cr.Name.String()
	inherit, inf := x.option("shell_environment_policy.inherit")
	switch inherit {
	case "none":
		r.Verdict, r.Why = model.ReachBlocked, x.texts("shell_environment_policy.inherit is none in "+inf)
		return r
	case "core":
		r.Verdict, r.Why = model.ReachBlocked, x.texts("shell_environment_policy.inherit is core in "+inf+", which passes only the basic vars")
		return r
	}
	if v, f := x.option("shell_environment_policy.ignore_default_excludes"); v == valueFalse && secretWords.MatchString(name) {
		r.Verdict, r.Why = model.ReachBlocked, x.texts("ignore_default_excludes is false in "+f+", so Codex drops names with KEY, SECRET or TOKEN")
		return r
	}
	if why, ok := x.envFiltered(name); ok {
		r.Verdict, r.Why = model.ReachBlocked, x.texts(why)
		return r
	}
	r.Verdict, r.Why = model.ReachSilent, x.texts("Codex passes "+cr.Via.String()+" vars to commands: inherit is all and ignore_default_excludes is true unless set", x.envKept(name))
	return r
}

// envFiltered says which pattern drops the var: an exclude, or an include
// list that leaves it out.
func (x *codex) envFiltered(name string) (string, bool) {
	includes, kept := 0, false
	for _, r := range x.perm.Rules {
		if !r.Origin.InEffect || !strings.HasPrefix(r.Rule.String(), "shell_environment_policy.") {
			continue
		}
		match := envMatch(r.Target.String(), name)
		switch {
		case r.Action == model.RuleDeny && match:
			return "excluded by " + r.Rule.String() + " in " + r.Origin.File.Text().String(), true
		case r.Action == model.RuleAllow:
			includes++
			kept = kept || match
		}
	}
	if includes > 0 && !kept {
		return "the include patterns in shell_environment_policy leave it out", true
	}
	return "", false
}

// envKept names the include pattern that keeps the var, when there is one.
func (x *codex) envKept(name string) string {
	for _, r := range x.perm.Rules {
		if r.Origin.InEffect && r.Action == model.RuleAllow && strings.HasPrefix(r.Rule.String(), "shell_environment_policy.") && envMatch(r.Target.String(), name) {
			return "kept by " + r.Rule.String()
		}
	}
	return ""
}

// envMatch matches Codex's case-insensitive env var patterns, where * is
// any text.
func envMatch(pattern, name string) bool {
	re := "(?i)^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + "$"
	ok, err := regexp.MatchString(re, name)
	return err == nil && ok
}
