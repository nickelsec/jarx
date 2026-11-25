package ui

import (
	"strconv"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
	"github.com/nickelsec/jarx/internal/report"
)

// inventoryData is the fixture with an agent, a skill and two MCP
// servers: a local one that started and lists two tools, and a remote one
// whose approval jarx can't see.
func inventoryData(t *testing.T) Data {
	t.Helper()
	f := newFixture(t)
	d := f.data()
	d.Scan.Agents = []report.AgentInfo{{Agent: model.AgentClaude, Name: "Claude Code", ConfigDir: f.path("/h/.claude"), Found: true,
		Installs: []model.Install{{Agent: model.AgentClaude, Method: model.InstallNative, Version: f.text("2.1.120"), OnPath: true}}}}
	d.Scan.Projects[0].Skills = []model.Skill{{Kind: model.SkillSkill, Name: f.text("release"), Origin: model.Origin{Agent: model.AgentClaude, File: f.path("/h/projects/tools/.claude/skills/release/SKILL.md")}}}
	d.Scan.Projects[0].Servers = []model.Server{
		{Name: f.text("notes-helper"), Transport: model.TransportStdio, Command: f.text("node"), Args: []redact.Text{f.text("server.js")}, Start: model.StartYes,
			Status: model.StatusListed, Offers: []model.Offer{{Kind: model.OfferTool, Name: f.text("save_note")}, {Kind: model.OfferTool, Name: f.text("delete_notes")}},
			Origin: model.Origin{Agent: model.AgentClaude, Scope: model.ScopeProject, File: f.path("/h/projects/tools/.mcp.json"), InEffect: true}},
	}
	d.Scan.Projects[1].Servers = []model.Server{
		{Name: f.text("search"), Transport: model.TransportHTTP, URL: f.text("https://mcp.example.com/sse"), Start: model.StartUnknown,
			Origin: model.Origin{Agent: model.AgentCodex, Scope: model.ScopeProject, File: f.path("/h/projects/app/.codex/config.toml")}},
	}
	return d
}

func TestInventoryIsInTheMenuAfterLLMReview(t *testing.T) {
	_, body, _ := get(t, inventoryData(t), "/inventory")

	side, _, _ := strings.Cut(body, "</aside>")
	if !order(side, `<a href="/llm"`, `<a href="/inventory" aria-current="page">`, "Inventory</a>") {
		t.Error("Inventory isn't in the menu right after LLM review, marked current")
	}
	if !strings.Contains(body, "<h1>Inventory</h1>") {
		t.Error("the page has no heading")
	}
}

func TestInventoryCountsWhatTheTerminalCounts(t *testing.T) {
	d := inventoryData(t)
	tot := report.Totals(d.Scan)

	_, body, _ := get(t, d, "/inventory")

	for _, want := range []struct {
		n     int
		label string
	}{{tot.Projects, "Projects"}, {tot.Skills, "Skills"}, {tot.Servers, "MCP servers"}, {tot.Instructions, "Instruction files"}} {
		if !order(body, `data-totals`, `<span class="stat-n">`+strconv.Itoa(want.n)+`</span><span class="faint">`+want.label+`</span>`) {
			t.Errorf("the totals lack %d %s", want.n, want.label)
		}
	}
}

func TestInventoryShowsTheAgents(t *testing.T) {
	_, body, _ := get(t, inventoryData(t), "/inventory")

	if !order(body, `<div class="agent-card">`, "Claude Code", "2.1.120", "native", "on PATH", "~/.claude") {
		t.Errorf("the agent card lacks its version, install or config dir:\n%s", body)
	}
}

func TestInventoryListsTheProjects(t *testing.T) {
	_, body, _ := get(t, inventoryData(t), "/inventory")

	_, projects, _ := strings.Cut(body, `id="inv-projects"`)
	if !order(projects, `href="/projects/0"`, `title="~/projects/tools">tools</span>`, "claude trusted", `<span class="n">1</span>`, `href="/projects/1"`, "app") {
		t.Errorf("the projects table lacks a project, its trust or its counts:\n%s", projects)
	}
}

func TestInventoryListsEveryMCPServer(t *testing.T) {
	_, body, _ := get(t, inventoryData(t), "/inventory")

	_, servers, _ := strings.Cut(body, `id="inv-servers"`)
	if !order(servers, "notes-helper", "claude", "tools", "node server.js", "starts", "listed", "2 tools") {
		t.Errorf("the local server's row lacks something:\n%s", servers)
	}
	if !order(servers, "search", "codex", "app", "mcp.example.com", "approval unknown") || strings.Contains(servers, "/sse") {
		t.Error("the remote server's row lacks something, or shows more of its URL than the host")
	}
}

func TestOnlyTrustedIsShownAsTrusted(t *testing.T) {
	d := inventoryData(t)
	d.Scan.Projects[1].Trust = []model.Trust{{Level: model.TrustUntrusted, Origin: model.Origin{Agent: model.AgentCodex}}}

	for _, page := range []string{"/inventory", "/projects/1"} {
		_, body, _ := get(t, d, page)

		if !strings.Contains(body, `<span class="pill plain">codex untrusted</span>`) || strings.Contains(body, `<span class="pill">codex untrusted</span>`) {
			t.Errorf("%s shows an untrusted project like a trusted one", page)
		}
	}
	if _, body, _ := get(t, d, "/inventory"); !strings.Contains(body, `<span class="pill">claude trusted</span>`) {
		t.Error("a trusted project isn't shown as trusted")
	}
}
