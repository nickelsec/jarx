package unknown

import (
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

func scrubber(t *testing.T) *redact.Scrubber {
	t.Helper()
	s, err := redact.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func u(s *redact.Scrubber, agent model.Agent, scope model.Scope, key, near, note string) model.Unknown {
	text := func(v string) redact.Text {
		x, _ := s.Scrub(v)
		return x
	}
	return model.Unknown{
		Key: text(key), Near: text(near), Note: text(note),
		Origin: model.Origin{Agent: agent, Scope: scope, File: model.NewPath(s, "settings.json"), InEffect: true},
	}
}

func TestEachUnknownKeyIsOneFinding(t *testing.T) {
	s := scrubber(t)
	for name, tc := range map[string]struct {
		in   model.Unknown
		id   string
		says string
	}{
		"plain unknown":        {u(s, model.AgentClaude, model.ScopeUser, "brandNewKey", "", ""), "JARX-UNKNOWN-001", "a newer Claude may know it"},
		"deprecated":           {u(s, model.AgentClaude, model.ScopeUser, "ignorePatterns", "", "deprecated: replaced by permissions.deny"), "JARX-UNKNOWN-001", "replaced by permissions.deny"},
		"typo of a plain key":  {u(s, model.AgentClaude, model.ScopeUser, "theem", "theme", ""), "JARX-UNKNOWN-002", "this file doesn't set theme"},
		"claude permissions":   {u(s, model.AgentClaude, model.ScopeUser, "permisions", "permissions", ""), "JARX-UNKNOWN-003", "this file doesn't set permissions"},
		"claude nested":        {u(s, model.AgentClaude, model.ScopeProject, "permissions.dney", "permissions.deny", ""), "JARX-UNKNOWN-003", ""},
		"claude sandbox":       {u(s, model.AgentClaude, model.ScopeUser, "sandbox.enabeld", "sandbox.enabled", ""), "JARX-UNKNOWN-003", ""},
		"claude lock":          {u(s, model.AgentClaude, model.ScopeManaged, "allowManagedHooksOnyl", "allowManagedHooksOnly", ""), "JARX-UNKNOWN-003", ""},
		"codex sandbox":        {u(s, model.AgentCodex, model.ScopeUser, "sandbox_workspace_write.network_acess", "sandbox_workspace_write.network_access", ""), "JARX-UNKNOWN-003", ""},
		"codex approvals":      {u(s, model.AgentCodex, model.ScopeProject, "aproval_policy", "approval_policy", ""), "JARX-UNKNOWN-003", ""},
		"codex plain":          {u(s, model.AgentCodex, model.ScopeUser, "mdoel", "model", ""), "JARX-UNKNOWN-002", ""},
		"any requirements key": {u(s, model.AgentCodex, model.ScopeRequirements, "allowed_web_search_mode", "allowed_web_search_modes", ""), "JARX-UNKNOWN-003", ""},
		"a loosening key":      {u(s, model.AgentClaude, model.ScopeProject, "enableAllProjectMcpServer", "enableAllProjectMcpServers", ""), "JARX-UNKNOWN-002", ""},
	} {
		got := Analyze(s, []model.Unknown{tc.in})
		if len(got) != 1 || got[0].RuleID != tc.id || !strings.Contains(got[0].Evidence.String(), tc.says) {
			t.Errorf("%s: findings = %+v, want one %s saying %q", name, got, tc.id, tc.says)
		}
	}
}

func TestTheFindingKeepsTheFileAndScope(t *testing.T) {
	s := scrubber(t)
	in := u(s, model.AgentClaude, model.ScopeProject, "permisions", "permissions", "")

	got := Analyze(s, []model.Unknown{in})

	if len(got) != 1 || got[0].Origin.Scope != model.ScopeProject || got[0].Origin.File.Raw() != "settings.json" {
		t.Errorf("findings = %+v, want the unknown's own origin", got)
	}
}

func TestRulesAreValid(t *testing.T) {
	if _, err := finding.NewRegistry(Rules()...); err != nil {
		t.Fatal(err)
	}
}
