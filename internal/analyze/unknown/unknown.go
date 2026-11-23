// Package unknown reports settings keys an agent's docs don't list. Most
// are typos, which means a setting someone thinks is on isn't; some are
// newer than jarx's key tables.
package unknown

import (
	"strings"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// Key is a key the agent's docs don't list.
func Key() finding.Rule {
	return finding.Rule{
		ID: "JARX-UNKNOWN-001", Severity: finding.Info,
		Title:  "a settings key isn't in the docs",
		Detail: "a settings key isn't in the agent's docs",
		Fix:    "check the spelling against the docs, or remove the key if nothing reads it",
	}
}

// Typo is a key that looks like a misspelled known key.
func Typo() finding.Rule {
	return finding.Rule{
		ID: "JARX-UNKNOWN-002", Severity: finding.Medium,
		Title:  "a settings key looks like a typo",
		Detail: "a settings key looks like a typo, so the setting it was meant to be isn't set",
		Fix:    "fix the spelling",
	}
}

// SafetyTypo is a typo of a key that protects you, so someone thinks
// they're protected when they're not.
func SafetyTypo() finding.Rule {
	return finding.Rule{
		ID: "JARX-UNKNOWN-003", Severity: finding.High,
		Title:  "a safety setting is misspelled",
		Detail: "a safety setting is misspelled, so the protection it was meant to add isn't on",
		Fix:    "fix the spelling, then check the setting applies",
	}
}

// Rules is every rule this analyzer can raise.
func Rules() []finding.Rule { return []finding.Rule{Key(), Typo(), SafetyTypo()} }

// claudeSafety are the Claude keys that restrict what the agent can do. A
// key that loosens things, like enableAllProjectMcpServers, isn't here: a
// typo there leaves you safer than you think.
//
//nolint:gochecknoglobals // fixed list, read only
var claudeSafety = []string{
	"disableAutoMode", "allowManagedPermissionRulesOnly", "allowManagedHooksOnly", "allowManagedMcpServersOnly",
	"disableAllHooks", "deniedMcpServers", "allowedMcpServers", "strictKnownMarketplaces", "allowedMarketplaces",
	"blockedMarketplaces", "allowedHttpHookUrls", "strictPluginOnlyCustomization",
}

// codexSafety are the Codex config keys that restrict the agent. Every
// requirements.toml key restricts, so those count without a list.
//
//nolint:gochecknoglobals // fixed list, read only
var codexSafety = []string{"sandbox_mode", "sandbox_workspace_write", "approval_policy", "default_permissions", "permissions", "shell_environment_policy"}

func under(key, prefix string) bool { return key == prefix || strings.HasPrefix(key, prefix+".") }

// safety reports whether near, the key a typo was meant to be, protects.
func safety(agent model.Agent, scope model.Scope, near string) bool {
	switch agent {
	case model.AgentClaude:
		return under(near, "permissions") || under(near, "sandbox") || underAny(near, claudeSafety)
	case model.AgentCodex:
		return scope == model.ScopeRequirements || underAny(near, codexSafety)
	case model.AgentJarx:
	}
	return false
}

func underAny(key string, prefixes []string) bool {
	for _, p := range prefixes {
		if under(key, p) {
			return true
		}
	}
	return false
}

func agentName(a model.Agent) string {
	switch a {
	case model.AgentClaude:
		return "Claude"
	case model.AgentCodex:
		return "Codex"
	case model.AgentJarx:
	}
	return string(a)
}

// Analyze makes one finding per unknown key.
func Analyze(s *redact.Scrubber, unknown []model.Unknown) []finding.Finding {
	out := make([]finding.Finding, 0, len(unknown))
	for _, u := range unknown {
		key, near := u.Key.String(), u.Near.String()
		rule := Key()
		ev := key + " isn't in the " + agentName(u.Origin.Agent) + " docs jarx knows; a newer " +
			agentName(u.Origin.Agent) + " may know it"
		switch {
		case near != "":
			rule = Typo()
			if safety(u.Origin.Agent, u.Origin.Scope, near) {
				rule = SafetyTypo()
			}
			ev = key + " looks like a typo of " + near + ", so this file doesn't set " + near
		case !u.Note.IsZero():
			ev = key + ": " + u.Note.String()
		}
		t, _ := s.Scrub(ev)
		out = append(out, rule.New(u.Origin, t))
	}
	return out
}
