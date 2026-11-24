package report

import (
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/model"
)

func (f scanFixture) egress(a model.Agent, area model.EgressArea, what, value string) model.Egress {
	return model.Egress{Agent: a, Area: area, What: f.text(what), Value: f.text(value), Origin: model.Origin{Agent: a, InEffect: true}}
}

func TestEachProjectSaysWhereItsAgentsTalkTo(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.Projects[0].Egress = []model.Egress{
		f.egress(model.AgentClaude, model.AreaModel, "default", "Anthropic's API"),
		f.egress(model.AgentClaude, model.AreaProxy, "HTTPS_PROXY", "http://proxy.example.com:3128"),
		f.egress(model.AgentClaude, model.AreaMCPHost, "tickets", "tickets.example.com"),
		f.egress(model.AgentClaude, model.AreaMCPHost, "search", "search.example.com"),
		f.egress(model.AgentCodex, model.AreaModel, "openai_base_url", "https://llm.example.com/v1"),
		f.egress(model.AgentCodex, model.AreaWebSearch, "web_search", "cached"),
	}

	out := render(Style{Width: 160}, v)

	want := `\- talks to: claude default API - 2 MCP hosts - proxy set - codex llm.example.com - web search cached` + "\n"
	if !strings.Contains(out, want) {
		t.Errorf("output =\n%s\nwant %q", out, want)
	}
}

func TestTheInventoryListsWhereEachAgentTalksTo(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.All = true
	proxy := f.egress(model.AgentClaude, model.AreaProxy, "HTTPS_PROXY", "http://proxy.example.com:3128")
	proxy.Note = f.text("proxy set, probes went direct")
	v.Projects[0].Egress = []model.Egress{f.egress(model.AgentClaude, model.AreaModel, "default", "Anthropic's API"), proxy}

	out := render(Style{Width: 200}, v)

	want := "    claude talks to\n      model endpoint  default  Anthropic's API\n" +
		"      proxy  HTTPS_PROXY  http://proxy.example.com:3128  env  proxy set, probes went direct\n"
	if !strings.Contains(out, want) {
		t.Errorf("output =\n%s\nwant %q", out, want)
	}
}

func TestNoProxyAloneIsntAProxy(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.Projects[0].Egress = []model.Egress{
		f.egress(model.AgentClaude, model.AreaModel, "default", "Anthropic's API"),
		f.egress(model.AgentClaude, model.AreaProxy, "NO_PROXY", "internal.example.com"),
	}

	if out := render(Style{Width: 160}, v); strings.Contains(out, "proxy set") {
		t.Errorf("output =\n%s\nwant no proxy set: NO_PROXY only lists hosts that skip one", out)
	}
}
