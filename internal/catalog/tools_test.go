package catalog

import (
	"slices"
	"testing"

	"github.com/nickelsec/jarx/internal/model"
)

func TestTheToolsCatalogLoads(t *testing.T) {
	for _, a := range []model.Agent{model.AgentClaude, model.AgentCodex} {
		ts := Tools(a)
		if len(ts) == 0 {
			t.Fatalf("Tools(%s) is empty", a)
		}
		if st := ToolsStamp(a); st.Version == "" || st.Checked == "" || st.Source == "" {
			t.Errorf("ToolsStamp(%s) = %+v, want a version, a date and a source", a, st)
		}
	}
}

// checkRow checks one row's columns: none empty, known channel and prompt
// values, and a rule and alias that name real tools.
func checkRow(t *testing.T, tool BuiltinTool) {
	t.Helper()
	channels := []Channel{ChannelFileRead, ChannelFileWrite, ChannelShell, ChannelNetwork, ChannelMCP, ChannelAgent, ChannelOther}
	prompts := []Prompts{PromptsYes, PromptsNo, PromptsSome, PromptsPolicy, PromptsUnknown}
	if tool.Name == "" || tool.What == "" || tool.Source == "" {
		t.Errorf("%s tool %+v has an empty column", tool.Agent, tool)
	}
	if !slices.Contains(channels, tool.Channel) || !slices.Contains(prompts, tool.Prompts) {
		t.Errorf("%s %s has channel %q, prompts %q", tool.Agent, tool.Name, tool.Channel, tool.Prompts)
	}
	for what, name := range map[string]string{"rule": tool.Rule, "alias": tool.Alias} {
		if _, ok := Tool(tool.Agent, name); name != "" && !ok {
			t.Errorf("%s %s's %s %q isn't a tool", tool.Agent, tool.Name, what, name)
		}
	}
}

func TestToolsFromTheDocs(t *testing.T) {
	for _, tc := range []struct {
		agent   model.Agent
		name    string
		channel Channel
		prompts Prompts
		rule    string
	}{
		{model.AgentClaude, "Read", ChannelFileRead, PromptsNo, "Read"},
		{model.AgentClaude, "Grep", ChannelFileRead, PromptsNo, "Read"},
		{model.AgentClaude, "Write", ChannelFileWrite, PromptsYes, "Edit"},
		{model.AgentClaude, "Bash", ChannelShell, PromptsYes, "Bash"},
		{model.AgentClaude, "Monitor", ChannelShell, PromptsYes, "Bash"},
		{model.AgentClaude, "WebFetch", ChannelNetwork, PromptsYes, "WebFetch"},
		{model.AgentClaude, "ExitPlanMode", ChannelOther, PromptsYes, "ExitPlanMode"},
		{model.AgentClaude, "Skill", ChannelOther, PromptsSome, "Skill"},
		{model.AgentCodex, "shell", ChannelShell, PromptsPolicy, ""},
		{model.AgentCodex, "apply_patch", ChannelFileWrite, PromptsPolicy, ""},
	} {
		got, ok := Tool(tc.agent, tc.name)
		if !ok || got.Channel != tc.channel || got.Prompts != tc.prompts || got.Rule != tc.rule {
			t.Errorf("Tool(%s, %s) = %+v, %v; want channel %s, prompts %s, rule %q", tc.agent, tc.name, got, ok, tc.channel, tc.prompts, tc.rule)
		}
	}
}

func TestOldNamesStillCount(t *testing.T) {
	// The docs say Task was renamed to Agent in 2.1.63 and Task(...) still
	// works; TaskOutput was removed in 2.1.277. A rule naming either isn't a
	// typo.
	if got, ok := Tool(model.AgentClaude, "Task"); !ok || got.Name != "Agent" {
		t.Errorf("Tool(Task) = %+v, %v; want the Agent tool", got, ok)
	}
	if got, ok := Tool(model.AgentClaude, "TaskOutput"); !ok || !got.Removed {
		t.Errorf("Tool(TaskOutput) = %+v, %v; want a known, removed tool", got, ok)
	}
	if _, ok := Tool(model.AgentClaude, "read"); ok {
		t.Error("Tool(read) found a tool; names are case-sensitive")
	}
	if !slices.Contains(ToolNames(model.AgentClaude), "Task") {
		t.Error("ToolNames leaves out the Task alias")
	}
}

func TestCoversComparesTheInstalledVersion(t *testing.T) {
	st := ToolsStamp(model.AgentClaude)
	for version, want := range map[string]Coverage{
		st.Version:              Covered,
		"2.1.1":                 Covered,
		"1.9.999":               Covered,
		"2.1.330 (Claude Code)": Covered,
		"9.0.0":                 Newer,
		"":                      UnknownVersion,
		"not a version":         UnknownVersion,
	} {
		if got := Covers(model.AgentClaude, version); got != want {
			t.Errorf("Covers(claude, %q) = %s, want %s", version, got, want)
		}
	}
	if got := Covers(model.AgentCodex, "codex-cli 999.0.0"); got != Newer {
		t.Errorf("Covers(codex, 999.0.0) = %s, want newer", got)
	}
	if got := Covers("someone", "1.0.0"); got != UnknownVersion {
		t.Errorf("Covers for an agent with no catalog = %s, want unknown", got)
	}
}

func TestEveryToolRowHoldsTogether(t *testing.T) {
	for _, a := range []model.Agent{model.AgentClaude, model.AgentCodex} {
		seen := map[string]bool{}
		for _, tool := range Tools(a) {
			if seen[tool.Name] {
				t.Errorf("%s %s is listed twice", a, tool.Name)
			}
			seen[tool.Name] = true
			checkRow(t, tool)
		}
	}
	if _, err := parseTools("claude\tX\tshell\tyes\tX\tgone\tsrc\twhat\n"); err == nil {
		t.Error("parseTools took a bad status")
	}
	if _, err := parseTools("claude\tX\tshell\n"); err == nil {
		t.Error("parseTools took a short row")
	}
}
