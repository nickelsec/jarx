package capability

import (
	"encoding/json"
	"os"
	"path/filepath"
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

// setup is one project with one listed server offering one tool, and the
// agent's permission settings.
type setup struct {
	Agent          string      `json:"agent"`
	Server         string      `json:"server"`
	Plugin         string      `json:"plugin"`
	Mode           string      `json:"mode"`
	Start          string      `json:"start"` // the start mode with no defaultMode
	ApprovalPolicy string      `json:"approvalPolicy"`
	Rules          [][2]string `json:"rules"`     // action and rule
	Approvals      [][2]string `json:"approvals"` // tool ("" for the server default) and mode
	Enabled        []string    `json:"enabled"`
	Disabled       []string    `json:"disabled"`
	Tool           string      `json:"tool"`
	Hints          []string    `json:"hints"`
}

func text(s *redact.Scrubber, v string) redact.Text {
	t, _ := s.Scrub(v)
	return t
}

// scrubAll scrubs each value, or is nil for none.
func scrubAll(s *redact.Scrubber, vs []string) []redact.Text {
	if vs == nil {
		return nil
	}
	out := make([]redact.Text, 0, len(vs))
	for _, v := range vs {
		out = append(out, text(s, v))
	}
	return out
}

func build(s *redact.Scrubber, u setup) []model.Project {
	if u.Agent == "" {
		u.Agent = "claude"
	}
	if u.Server == "" {
		u.Server = "github"
	}
	a := model.Agent(u.Agent)
	o := model.Origin{Agent: a, Scope: model.ScopeUser, File: model.NewPath(s, "/home/dev/.claude.json"), InEffect: true}
	offer := model.Offer{Kind: model.OfferTool, Name: text(s, u.Tool), Text: text(s, `{"name": "`+u.Tool+`"}`)}
	offer.Hints = scrubAll(s, u.Hints)
	srv := model.Server{Name: text(s, u.Server), Plugin: text(s, u.Plugin), Start: model.StartYes, Status: model.StatusListed, Origin: o, Offers: []model.Offer{offer}}
	if u.Enabled != nil {
		srv.EnabledTools = append([]redact.Text{}, scrubAll(s, u.Enabled)...)
	}
	srv.DisabledTools = scrubAll(s, u.Disabled)
	for _, ap := range u.Approvals {
		srv.Approvals = append(srv.Approvals, model.Pair{Key: text(s, ap[0]), Value: text(s, ap[1])})
	}
	perm := model.Permissions{Agent: a}
	ro := model.Origin{Agent: a, Scope: model.ScopeUser, File: model.NewPath(s, "/home/dev/.claude/settings.json"), InEffect: true}
	for _, r := range u.Rules {
		target := ""
		if i := strings.IndexByte(r[1], '('); i >= 0 {
			target = strings.TrimSuffix(r[1][i+1:], ")")
		}
		perm.Rules = append(perm.Rules, model.PermissionRule{Action: model.RuleAction(r[0]), Rule: text(s, r[1]), Target: text(s, target), Origin: ro})
	}
	if u.Mode != "" {
		perm.DefaultMode.Layers = []model.Layer[redact.Text]{{Value: text(s, u.Mode), Origin: ro}}
		perm.StartMode, perm.StartWhy = text(s, u.Mode), text(s, "defaultMode is "+u.Mode)
	}
	if u.Start != "" {
		perm.StartMode, perm.StartWhy = text(s, u.Start), text(s, "the built-in start mode")
	}
	if u.ApprovalPolicy != "" {
		perm.Options = []model.Option{{Key: text(s, "approval_policy"), Setting: model.Setting[redact.Text]{Layers: []model.Layer[redact.Text]{{Value: text(s, u.ApprovalPolicy), Origin: ro}}}}}
	}
	return []model.Project{{Path: model.NewPath(s, "/p"), Servers: []model.Server{srv}, Permissions: []model.Permissions{perm}}}
}

func access(t *testing.T, u setup) (model.ToolAccess, string) {
	t.Helper()
	s := scrubber(t)
	ps := build(s, u)
	Settle(s, ps)
	o := ps[0].Servers[0].Offers[0]
	return o.Access, o.AccessWhy.String()
}

func TestClaudeAccess(t *testing.T) {
	for name, tc := range map[string]struct {
		u    setup
		want model.ToolAccess
	}{
		"no rule asks":                                {setup{Tool: "search"}, model.AccessAsks},
		"allow by name":                               {setup{Tool: "search", Rules: [][2]string{{"allow", "mcp__github__search"}}}, model.AccessNoAsk},
		"allow by wildcard":                           {setup{Tool: "search", Rules: [][2]string{{"allow", "mcp__github__*"}}}, model.AccessNoAsk},
		"allow by server":                             {setup{Tool: "search", Rules: [][2]string{{"allow", "mcp__github"}}}, model.AccessNoAsk},
		"allow for another server":                    {setup{Tool: "search", Rules: [][2]string{{"allow", "mcp__gitlab__*"}}}, model.AccessAsks},
		"allow for another tool":                      {setup{Tool: "search", Rules: [][2]string{{"allow", "mcp__github__create"}}}, model.AccessAsks},
		"allow with a specifier":                      {setup{Tool: "search", Rules: [][2]string{{"allow", "mcp__github__search(query)"}}}, model.AccessAsks},
		"deny wins over allow":                        {setup{Tool: "search", Rules: [][2]string{{"allow", "mcp__github__*"}, {"deny", "mcp__github__search"}}}, model.AccessDenied},
		"ask wins over allow":                         {setup{Tool: "search", Rules: [][2]string{{"allow", "mcp__github"}, {"ask", "mcp__github__search"}}}, model.AccessAsks},
		"bypass mode":                                 {setup{Tool: "search", Mode: "bypassPermissions"}, model.AccessNoAsk},
		"dontAsk denies the rest":                     {setup{Tool: "search", Mode: "dontAsk"}, model.AccessDenied},
		"dontAsk keeps an allow":                      {setup{Tool: "search", Mode: "dontAsk", Rules: [][2]string{{"allow", "mcp__github__*"}}}, model.AccessNoAsk},
		"auto mode":                                   {setup{Tool: "search", Mode: "auto"}, model.AccessMayNotAsk},
		"deny holds in bypass":                        {setup{Tool: "search", Mode: "bypassPermissions", Rules: [][2]string{{"deny", "mcp__github"}}}, model.AccessDenied},
		"dotted name":                                 {setup{Server: "my.server", Tool: "t", Rules: [][2]string{{"allow", "mcp__my_server__*"}}}, model.AccessNoAsk},
		"plugin server":                               {setup{Server: "db", Plugin: "my-plugin@market", Tool: "q", Rules: [][2]string{{"allow", "mcp__plugin_my-plugin_db__*"}}}, model.AccessNoAsk},
		"plugin needs the long form":                  {setup{Server: "db", Plugin: "my-plugin@market", Tool: "q", Rules: [][2]string{{"allow", "mcp__db__*"}}}, model.AccessAsks},
		"double underscore, bare allow doesn't match": {setup{Server: "reports__v2", Tool: "t", Rules: [][2]string{{"allow", "mcp__reports__v2"}}}, model.AccessAsks},
		"double underscore, wildcard allow matches":   {setup{Server: "reports__v2", Tool: "t", Rules: [][2]string{{"allow", "mcp__reports__v2__*"}}}, model.AccessNoAsk},
		"double underscore, short deny covers":        {setup{Server: "reports__v2", Tool: "t", Rules: [][2]string{{"deny", "mcp__reports"}}}, model.AccessDenied},
		// With no defaultMode, a session starts in the agent's built-in mode,
		// which the adapter works out.
		"starts in auto with no rule":     {setup{Tool: "search", Start: "auto"}, model.AccessMayNotAsk},
		"starts in default with no rule":  {setup{Tool: "search", Start: "default"}, model.AccessAsks},
		"an ask still asks in auto start": {setup{Tool: "search", Start: "auto", Rules: [][2]string{{"ask", "mcp__github__search"}}}, model.AccessAsks},
	} {
		t.Run(name, func(t *testing.T) {
			if got, why := access(t, tc.u); got != tc.want || why == "" {
				t.Errorf("access = %s (%q), want %s with a why", got, why, tc.want)
			}
		})
	}
}

func TestCodexAccess(t *testing.T) {
	codex := func(u setup) setup { u.Agent = "codex"; return u }
	for name, tc := range map[string]struct {
		u    setup
		want model.ToolAccess
	}{
		"disabled":                      {codex(setup{Tool: "t", Disabled: []string{"t"}}), model.AccessHidden},
		"not in enabled_tools":          {codex(setup{Tool: "t", Enabled: []string{"other"}}), model.AccessHidden},
		"empty enabled_tools":           {codex(setup{Tool: "t", Enabled: []string{}}), model.AccessHidden},
		"in enabled_tools":              {codex(setup{Tool: "t", Enabled: []string{"t"}, Approvals: [][2]string{{"", "prompt"}}}), model.AccessAsks},
		"disabled after enabled":        {codex(setup{Tool: "t", Enabled: []string{"t"}, Disabled: []string{"t"}}), model.AccessHidden},
		"prompt":                        {codex(setup{Tool: "t", Approvals: [][2]string{{"", "prompt"}}}), model.AccessAsks},
		"writes, not read-only":         {codex(setup{Tool: "t", Approvals: [][2]string{{"", "writes"}}}), model.AccessAsks},
		"writes, read-only":             {codex(setup{Tool: "t", Hints: []string{"readOnlyHint"}, Approvals: [][2]string{{"", "writes"}}}), model.AccessMayNotAsk},
		"approve":                       {codex(setup{Tool: "t", Approvals: [][2]string{{"", "approve"}}}), model.AccessMayNotAsk},
		"tool mode beats server":        {codex(setup{Tool: "t", Approvals: [][2]string{{"", "approve"}, {"t", "prompt"}}}), model.AccessAsks},
		"unset, destructive":            {codex(setup{Tool: "t", Hints: []string{"destructiveHint"}}), model.AccessAsks},
		"unset, read beats destructive": {codex(setup{Tool: "t", Hints: []string{"destructiveHint", "readOnlyHint"}}), model.AccessMayNotAsk},
		"unset, never asks":             {codex(setup{Tool: "t", ApprovalPolicy: "never"}), model.AccessNoAsk},
		"unset, on-request":             {codex(setup{Tool: "t", ApprovalPolicy: "on-request"}), model.AccessMayNotAsk},
	} {
		t.Run(name, func(t *testing.T) {
			if got, why := access(t, tc.u); got != tc.want || why == "" {
				t.Errorf("access = %s (%q), want %s with a why", got, why, tc.want)
			}
		})
	}
}

func TestOnlyListedServersAreSettled(t *testing.T) {
	s := scrubber(t)
	ps := build(s, setup{Tool: "t"})
	ps[0].Servers[0].Status = model.StatusTimedOut

	Settle(s, ps)

	if got := ps[0].Servers[0].Offers[0].Access; got != model.AccessUnsettled {
		t.Errorf("access = %s, want nothing for a server that wasn't listed", got)
	}
}

func ids(fs []finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

func TestEveryRuleHasPoisonedAndCleanFixtures(t *testing.T) {
	known := map[string]bool{}
	for _, r := range Rules() {
		known[r.ID] = true
		for _, kind := range []string{"poisoned", "clean"} {
			if entries, err := os.ReadDir(filepath.Join("testdata", r.ID, kind)); err != nil || len(entries) == 0 {
				t.Errorf("%s has no %s fixtures", r.ID, kind)
			}
		}
	}
	dirs, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dirs {
		if !known[d.Name()] {
			t.Errorf("testdata/%s is for a rule that doesn't exist", d.Name())
		}
	}
}

func TestFixtures(t *testing.T) {
	s := scrubber(t)
	for _, r := range Rules() {
		for _, kind := range []string{"poisoned", "clean"} {
			dir := filepath.Join("testdata", r.ID, kind)
			entries, _ := os.ReadDir(dir)
			for _, e := range entries {
				t.Run(r.ID+"/"+kind+"/"+e.Name(), func(t *testing.T) {
					body, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // G304: our own fixture dir
					if err != nil {
						t.Fatal(err)
					}
					var u setup
					if err := json.Unmarshal(body, &u); err != nil {
						t.Fatal(err)
					}
					ps := build(s, u)
					Settle(s, ps)
					got := Analyze(s, ps)
					raised := false
					for _, f := range got {
						raised = raised || f.RuleID == r.ID
					}
					if raised != (kind == "poisoned") {
						t.Errorf("findings = %q, want %s raised: %v", ids(got), r.ID, kind == "poisoned")
					}
				})
			}
		}
	}
}

func TestRulesRegister(t *testing.T) {
	if _, err := finding.NewRegistry(Rules()...); err != nil {
		t.Fatal(err)
	}
}

// moreTools adds tools by name to the one server build made.
func moreTools(s *redact.Scrubber, ps []model.Project, names ...string) {
	for _, n := range names {
		ps[0].Servers[0].Offers = append(ps[0].Servers[0].Offers, model.Offer{Kind: model.OfferTool, Name: text(s, n), Text: text(s, `{"name": "`+n+`"}`)})
	}
}

func TestOneAllowRuleIsOneFinding(t *testing.T) {
	for name, u := range map[string]setup{
		"claude wildcard": {Tool: "delete_repo", Rules: [][2]string{{"allow", "mcp__github__*"}}},
		"codex default":   {Agent: "codex", Tool: "delete_repo", Approvals: [][2]string{{"", "approve"}}},
	} {
		t.Run(name, func(t *testing.T) {
			s := scrubber(t)
			ps := build(s, u)
			moreTools(s, ps, "push_files", "list_issues")
			Settle(s, ps)

			var caps []string
			for _, f := range Analyze(s, ps) {
				if f.RuleID == DestructiveRunsUnasked().ID {
					caps = append(caps, f.Evidence.String())
				}
			}

			if len(caps) != 1 || !strings.Contains(caps[0], "delete_repo") || !strings.Contains(caps[0], "push_files") || strings.Contains(caps[0], "list_issues") {
				t.Errorf("CAP-001 evidence = %q, want one finding naming delete_repo and push_files, not list_issues", caps)
			}
		})
	}
}
