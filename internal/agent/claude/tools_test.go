package claude

import (
	"testing"

	"github.com/nickelsec/jarx/internal/model"
)

func TestRulesNamingAToolTheCatalogDoesntKnowAreMarked(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude/settings.json": `{"permissions": {
			"deny": ["Raed(./.env)", "Read(./secrets/**)", "mcp__github__delete_repo", "Task(Explore)", "TaskOutput", "FancyNewTool", "read"],
			"ask": ["WebFech(domain:example.com)"]
		}}`,
	})

	perm, _, _ := settingsFor(t, c, model.TrustUntrusted)

	for rule, want := range map[string]struct {
		unknown bool
		near    string
	}{
		"Raed(./.env)":                {true, "Read"},
		"Read(./secrets/**)":          {false, ""},
		"mcp__github__delete_repo":    {false, ""}, // MCP tools are probe's to list
		"Task(Explore)":               {false, ""}, // the old name of Agent
		"TaskOutput":                  {false, ""}, // removed, not a typo
		"FancyNewTool":                {true, ""},  // maybe newer than the catalog
		"read":                        {true, "Read"},
		"WebFech(domain:example.com)": {true, "WebFetch"},
	} {
		r := findRule(t, perm, rule, model.ScopeUser)
		if r.ToolUnknown != want.unknown || r.NearTool.String() != want.near {
			t.Errorf("%s: unknown = %v, near = %q; want %v, %q", rule, r.ToolUnknown, r.NearTool.String(), want.unknown, want.near)
		}
	}
}
