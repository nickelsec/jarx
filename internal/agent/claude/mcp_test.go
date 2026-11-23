package claude

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/catalog"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// claudeJSON builds a ~/.claude.json with user servers and local servers for
// /p. extra goes inside the /p entry, like a disabledMcpServers list.
func claudeJSON(user, local, extra string) string {
	entry := `"mcpServers": {` + local + `}`
	if extra != "" {
		entry += ", " + extra
	}
	return `{"numStartups": 3, "mcpServers": {` + user + `}, "projects": {"/p": {"hasTrustDialogAccepted": true, ` + entry + `}}}`
}

func mcpJSON(servers string) string { return `{"mcpServers": {` + servers + `}}` }

const (
	stdioGit  = `"git": {"command": "npx", "args": ["-y", "git-mcp"]}`
	httpDocs  = `"docs": {"type": "http", "url": "https://docs.example.com/mcp"}`
	approveAl = `{"enableAllProjectMcpServers": true}`
)

func serversFor(t *testing.T, c agent.Context, trust model.TrustLevel) model.Project {
	t.Helper()
	p := project(c, trust)
	ps := []model.Project{p}
	Adapter{}.Extensions(c, ps)
	return ps[0]
}

func findServer(t *testing.T, p model.Project, scope model.Scope, name string) model.Server {
	t.Helper()
	for _, s := range p.Servers {
		if s.Origin.Scope == scope && s.Name.String() == name {
			return s
		}
	}
	t.Fatalf("no %s server %q in %v", scope, name, serverViews(p.Servers))
	return model.Server{}
}

type serverView struct {
	name  string
	scope model.Scope
	start model.StartState
	why   string
}

func serverViews(ss []model.Server) []serverView {
	out := make([]serverView, 0, len(ss))
	for _, s := range ss {
		out = append(out, serverView{s.Name.String(), s.Origin.Scope, s.Start, s.Origin.Why.String() + s.Note.String()})
	}
	return out
}

func texts(ts []model.Pair) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Key.String()+"="+t.Value.String())
	}
	return out
}

func TestServersComeFromEachScope(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude.json":          claudeJSON(stdioGit, httpDocs, ""),
		".claude/settings.json": approveAl,
		"p/.mcp.json": mcpJSON(`"db": {"type": "stdio", "command": "node", "args": ["db.js"], "env": {"DB": "x"}},
			"feed": {"type": "sse", "url": "https://feed.example.com/sse", "headers": {"X-Team": "a"}}`),
	})

	p := serversFor(t, c, model.TrustTrusted)

	for _, tc := range []struct {
		scope      model.Scope
		name, want string
	}{
		{model.ScopeUser, "git", "stdio | npx -y git-mcp |  |  | "},
		{model.ScopeLocal, "docs", "http |  | https://docs.example.com/mcp |  | "},
		{model.ScopeProject, "db", "stdio | node db.js |  | DB=x | "},
		{model.ScopeProject, "feed", "sse |  | https://feed.example.com/sse |  | X-Team=a"},
	} {
		s := findServer(t, p, tc.scope, tc.name)
		if got := describe(s); got != tc.want || s.Start != model.StartYes || !s.Origin.InEffect {
			t.Errorf("%s %s = %q, %s (%q); want %q and starts", tc.scope, tc.name, got, s.Start, s.Origin.Why, tc.want)
		}
	}
	if len(p.Servers) != 4 {
		t.Errorf("servers = %v, want 4", serverViews(p.Servers))
	}
}

// describe is a server's transport, command line, URL, env and headers.
func describe(s model.Server) string {
	cmd := make([]string, 0, 1+len(s.Args))
	cmd = append(cmd, s.Command.String())
	for _, a := range s.Args {
		cmd = append(cmd, a.String())
	}
	return strings.Join([]string{
		string(s.Transport), strings.TrimSpace(strings.Join(cmd, " ")), s.URL.String(),
		strings.Join(texts(s.Env), ","), strings.Join(texts(s.Headers), ","),
	}, " | ")
}

func TestStreamableHTTPIsAnAliasForHTTP(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude.json": claudeJSON(`"a": {"type": "streamable-http", "url": "https://a.example.com"},
			"w": {"type": "ws", "url": "wss://w.example.com"}, "odd": {"type": "carrier-pigeon"}`, "", ""),
	})

	p := serversFor(t, c, model.TrustTrusted)

	if s := findServer(t, p, model.ScopeUser, "a"); s.Transport != model.TransportHTTP {
		t.Errorf("streamable-http = %s, want http", s.Transport)
	}
	if s := findServer(t, p, model.ScopeUser, "w"); s.Transport != model.TransportWS {
		t.Errorf("ws = %s, want ws", s.Transport)
	}
	if s := findServer(t, p, model.ScopeUser, "odd"); s.Transport != model.TransportUnknown || s.Start != model.StartNo {
		t.Errorf("unknown type = %s %s, want unknown and not started", s.Transport, s.Start)
	}
}

func TestProjectServersNeedApproval(t *testing.T) {
	for name, tc := range map[string]struct {
		files map[string]string
		trust model.TrustLevel
		want  model.StartState
	}{
		"no approval anywhere": {nil, model.TrustTrusted, model.StartUnknown},
		"user approves all":    {map[string]string{".claude/settings.json": approveAl}, model.TrustUntrusted, model.StartYes},
		"user approves by name": {map[string]string{".claude/settings.json": `{"enabledMcpjsonServers": ["db"]}`},
			model.TrustUntrusted, model.StartYes},
		"user approves another name": {map[string]string{".claude/settings.json": `{"enabledMcpjsonServers": ["other"]}`},
			model.TrustTrusted, model.StartUnknown},
		"trusted project approves": {map[string]string{"p/.claude/settings.json": approveAl}, model.TrustTrusted, model.StartYes},
		"untrusted project can't approve itself": {map[string]string{"p/.claude/settings.json": approveAl},
			model.TrustUntrusted, model.StartUnknown},
		"local approval waits for trust": {map[string]string{"p/.claude/settings.local.json": `{"enabledMcpjsonServers": ["db"]}`},
			model.TrustUntrusted, model.StartUnknown},
		"trusted local approves": {map[string]string{"p/.claude/settings.local.json": `{"enabledMcpjsonServers": ["db"]}`},
			model.TrustTrusted, model.StartYes},
		"a rejection in any file wins": {map[string]string{
			".claude/settings.json":   approveAl,
			"p/.claude/settings.json": `{"disabledMcpjsonServers": ["db"]}`,
		}, model.TrustUntrusted, model.StartNo},
	} {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{"p/.mcp.json": mcpJSON(`"db": {"command": "node", "args": ["db.js"]}`)}
			maps.Copy(files, tc.files)
			c := fakeHome(t, files)

			s := findServer(t, serversFor(t, c, tc.trust), model.ScopeProject, "db")

			if s.Start != tc.want || s.Origin.InEffect != (tc.want == model.StartYes) {
				t.Errorf("db = %s, in effect %v (%q), want %s", s.Start, s.Origin.InEffect, s.Origin.Why, tc.want)
			}
			if tc.want != model.StartYes && s.Origin.Why.IsZero() {
				t.Error("a server that doesn't start needs a why")
			}
		})
	}
}

func TestMcpPanelToggleTurnsOffAServer(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude.json": claudeJSON(stdioGit+", "+httpDocs, "", `"disabledMcpServers": ["git"], "enabledMcpServers": ["docs"]`),
	})

	p := serversFor(t, c, model.TrustTrusted)

	if s := findServer(t, p, model.ScopeUser, "git"); s.Start != model.StartNo || s.Origin.Why.IsZero() {
		t.Errorf("git = %s (%q), want not started with a why", s.Start, s.Origin.Why)
	}
	if s := findServer(t, p, model.ScopeUser, "docs"); s.Start != model.StartYes {
		t.Errorf("docs = %s, want enabledMcpServers to change nothing for a configured server", s.Start)
	}
}

func TestManagedMcpFileTakesExclusiveControl(t *testing.T) {
	c := managedHome(t,
		map[string]string{
			".claude.json":          claudeJSON(stdioGit, "", ""),
			".claude/settings.json": approveAl,
			"p/.mcp.json":           mcpJSON(httpDocs),
		},
		map[string]string{"managed-mcp.json": mcpJSON(`"corp": {"type": "http", "url": "https://corp.example.com/mcp"}`)}, nil)

	p := serversFor(t, c, model.TrustTrusted)

	if s := findServer(t, p, model.ScopeManaged, "corp"); s.Start != model.StartYes {
		t.Errorf("corp = %s (%q), want it to start", s.Start, s.Origin.Why)
	}
	for _, s := range []model.Server{findServer(t, p, model.ScopeUser, "git"), findServer(t, p, model.ScopeProject, "docs")} {
		if s.Start != model.StartNo || !strings.Contains(s.Origin.Why.String(), "managed-mcp.json") {
			t.Errorf("%s %s = %s (%q), want not started because of managed-mcp.json", s.Origin.Scope, s.Name, s.Start, s.Origin.Why)
		}
	}
}

func TestBrokenManagedMcpFileLeavesOthersMaybe(t *testing.T) {
	c := managedHome(t, map[string]string{".claude.json": claudeJSON(stdioGit, "", "")},
		map[string]string{"managed-mcp.json": `{"mcpServers": `}, nil)

	p := serversFor(t, c, model.TrustTrusted)

	if s := findServer(t, p, model.ScopeUser, "git"); s.Start != model.StartMaybe || s.Note.IsZero() {
		t.Errorf("git = %s (%q), want may start with a note", s.Start, s.Note)
	}
}

func TestStrictPluginOnlyMcpStopsUserAndProjectServers(t *testing.T) {
	c := managedHome(t, map[string]string{".claude.json": claudeJSON(stdioGit, "", "")},
		map[string]string{"managed-settings.json": `{"strictPluginOnlyCustomization": ["mcp"]}`}, nil)

	p := serversFor(t, c, model.TrustTrusted)

	if s := findServer(t, p, model.ScopeUser, "git"); s.Start != model.StartNo {
		t.Errorf("git = %s, want not started under strictPluginOnlyCustomization", s.Start)
	}
}

func TestDenyAndAllowLists(t *testing.T) {
	for name, tc := range map[string]struct {
		managed, user string
		want          model.StartState
	}{
		"no lists":                  {`{}`, `{}`, model.StartYes},
		"denied by name":            {`{"deniedMcpServers": [{"serverName": "git"}]}`, `{}`, model.StartNo},
		"user deny counts too":      {`{}`, `{"deniedMcpServers": [{"serverName": "git"}]}`, model.StartNo},
		"denied by exact command":   {`{"deniedMcpServers": [{"serverCommand": ["npx", "-y", "git-mcp"]}]}`, `{}`, model.StartNo},
		"command must match whole":  {`{"deniedMcpServers": [{"serverCommand": ["npx", "git-mcp"]}]}`, `{}`, model.StartYes},
		"empty allowlist":           {`{"allowedMcpServers": []}`, `{}`, model.StartNo},
		"allowed by command":        {`{"allowedMcpServers": [{"serverCommand": ["npx", "-y", "git-mcp"]}]}`, `{}`, model.StartYes},
		"allowed by another name":   {`{"allowedMcpServers": [{"serverName": "other"}]}`, `{}`, model.StartNo},
		"name counts with no cmds":  {`{"allowedMcpServers": [{"serverName": "git"}]}`, `{}`, model.StartYes},
		"name ignored next to cmds": {`{"allowedMcpServers": [{"serverName": "git"}, {"serverCommand": ["x"]}]}`, `{}`, model.StartNo},
		"user allow widens":         {`{"allowedMcpServers": []}`, `{"allowedMcpServers": [{"serverName": "git"}]}`, model.StartYes},
		"managed only drops user allow": {`{"allowManagedMcpServersOnly": true, "allowedMcpServers": []}`,
			`{"allowedMcpServers": [{"serverName": "git"}]}`, model.StartNo},
		"deny with a variable is unsettled": {`{"deniedMcpServers": [{"serverCommand": ["${BIN}", "-y", "git-mcp"]}]}`, `{}`, model.StartMaybe},
	} {
		t.Run(name, func(t *testing.T) {
			c := managedHome(t,
				map[string]string{".claude.json": claudeJSON(stdioGit, "", ""), ".claude/settings.json": tc.user},
				map[string]string{"managed-settings.json": tc.managed}, nil)

			s := findServer(t, serversFor(t, c, model.TrustTrusted), model.ScopeUser, "git")

			if s.Start != tc.want {
				t.Errorf("git = %s (%q %q), want %s", s.Start, s.Origin.Why, s.Note, tc.want)
			}
		})
	}
}

func TestAllowManagedOnlyComesFromEveryAdminSource(t *testing.T) {
	// The registry policy is the source in use, so the file's
	// allowedMcpServers alone would be ignored; its lock still counts.
	c := managedHome(t,
		map[string]string{".claude.json": claudeJSON(stdioGit, "", ""), ".claude/settings.json": `{"allowedMcpServers": [{"serverName": "git"}]}`},
		map[string]string{"managed-settings.json": `{"allowManagedMcpServersOnly": true, "allowedMcpServers": []}`},
		fakeRegistry{hklmSettings: `{"model": "x"}`})

	s := findServer(t, serversFor(t, c, model.TrustTrusted), model.ScopeUser, "git")

	if s.Start != model.StartNo {
		t.Errorf("git = %s (%q), want the lock from the unselected file to apply", s.Start, s.Origin.Why)
	}
}

func TestDenyComesFromEveryAdminSource(t *testing.T) {
	c := managedHome(t, map[string]string{".claude.json": claudeJSON(stdioGit, "", "")},
		map[string]string{"managed-settings.json": `{"deniedMcpServers": [{"serverName": "git"}]}`},
		fakeRegistry{hklmSettings: `{"model": "x"}`})

	s := findServer(t, serversFor(t, c, model.TrustTrusted), model.ScopeUser, "git")

	if s.Start != model.StartNo {
		t.Errorf("git = %s, want the deny from the unselected file to apply", s.Start)
	}
}

func TestHKCUDenyDoesntCountNextToAnAdminSource(t *testing.T) {
	c := managedHome(t, map[string]string{".claude.json": claudeJSON(stdioGit, "", "")},
		map[string]string{"managed-settings.json": `{"model": "x"}`},
		fakeRegistry{hkcuSettings: `{"deniedMcpServers": [{"serverName": "git"}]}`})

	s := findServer(t, serversFor(t, c, model.TrustTrusted), model.ScopeUser, "git")

	if s.Start != model.StartYes {
		t.Errorf("git = %s (%q), want HKCU ignored when an admin source is present", s.Start, s.Origin.Why)
	}
}

func TestServerURLPatterns(t *testing.T) {
	for _, tc := range []struct {
		pattern, url string
		want         bool
	}{
		{"https://mcp.example.com/*", "https://mcp.example.com/api", true},
		{"https://mcp.example.com", "https://mcp.example.com/any/path", true},
		{"https://mcp.example.com/*", "https://mcp.example.com:8443/api", false},
		{"https://mcp.example.com:8443/*", "https://mcp.example.com:8443/api", true},
		{"https://mcp.example.com:*/*", "https://mcp.example.com/api", true},
		{"https://*.example.com/*", "https://a.example.com:9000/x", true},
		{"https://*.example.com/*", "https://example.org/x", false},
		{"http://localhost:*/*", "http://localhost:3000/mcp", true},
		{"*://mcp.example.com/*", "http://mcp.example.com/x", true},
		{"*://mcp.example.com/*", "http://mcp.example.com:8080/x", false},
		{"https://Mcp.Example.com/*", "https://mcp.example.com./api", true},
		{"https://mcp.example.com/API/*", "https://mcp.example.com/api/x", false},
		{"https://mcp.example.com/*", "https://mcp.example.com:443/api", true},
		{"https://mcp.example.com/*", "http://mcp.example.com/api", false},
	} {
		if got := urlMatches(tc.pattern, tc.url); got != tc.want {
			t.Errorf("urlMatches(%q, %q) = %v, want %v", tc.pattern, tc.url, got, tc.want)
		}
	}
}

func TestRemoteServersMatchByURL(t *testing.T) {
	c := managedHome(t, map[string]string{".claude.json": claudeJSON(httpDocs, "", "")},
		map[string]string{"managed-settings.json": `{"allowedMcpServers": [{"serverUrl": "https://*.example.com/*"}, {"serverName": "nope"}]}`}, nil)

	s := findServer(t, serversFor(t, c, model.TrustTrusted), model.ScopeUser, "docs")

	if s.Start != model.StartYes {
		t.Errorf("docs = %s (%q), want the url entry to allow it", s.Start, s.Origin.Why)
	}
}

func TestSameNameUsesTheHighestScopeWhole(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude.json":          claudeJSON(`"git": {"command": "npx", "args": ["git-mcp"], "env": {"A": "1"}}`, `"git": {"command": "uvx", "args": ["git-mcp"]}`, ""),
		".claude/settings.json": approveAl,
		"p/.mcp.json":           mcpJSON(`"git": {"command": "node", "args": ["git.js"]}`),
	})

	p := serversFor(t, c, model.TrustTrusted)

	if s := findServer(t, p, model.ScopeLocal, "git"); s.Start != model.StartYes || len(s.Env) != 0 {
		t.Errorf("local git = %s env %q, want it to win with no fields merged in", s.Start, texts(s.Env))
	}
	for _, scope := range []model.Scope{model.ScopeProject, model.ScopeUser} {
		s := findServer(t, p, scope, "git")
		if s.Start != model.StartNo || !strings.Contains(s.Origin.Why.String(), "local") {
			t.Errorf("%s git = %s (%q), want overridden by the local one", scope, s.Start, s.Origin.Why)
		}
	}
}

func TestSameNameBelowAServerThatWontStartMayStart(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude.json": claudeJSON(stdioGit, "", ""),
		"p/.mcp.json":  mcpJSON(`"git": {"command": "node", "args": ["evil.js"]}`),
	})

	p := serversFor(t, c, model.TrustTrusted)

	if s := findServer(t, p, model.ScopeProject, "git"); s.Start != model.StartUnknown {
		t.Errorf("project git = %s, want approval unknown", s.Start)
	}
	if s := findServer(t, p, model.ScopeUser, "git"); s.Start != model.StartMaybe || s.Note.IsZero() || !s.Origin.InEffect {
		t.Errorf("user git = %s in effect %v (%q), want may start with a note", s.Start, s.Origin.InEffect, s.Note)
	}
}

func TestManagedProvidedServers(t *testing.T) {
	c := managedHome(t,
		map[string]string{".claude.json": claudeJSON(`"search": {"type": "http", "url": "https://other.example.com"}`, "", "")},
		map[string]string{"managed-settings.json": `{"allowedMcpServers": [], "managedMcpServers": {
			"search": {"type": "http", "url": "https://search.example.com/mcp"},
			"plain": {"type": "http", "url": "http://plain.example.com/mcp"},
			"local": {"type": "stdio", "command": "srv"},
			"vars": {"type": "http", "url": "https://${HOST}/mcp"}}}`}, nil)

	p := serversFor(t, c, model.TrustTrusted)

	if s := findServer(t, p, model.ScopeManaged, "search"); s.Start != model.StartYes {
		t.Errorf("search = %s (%q), want it to start without an allowlist entry", s.Start, s.Origin.Why)
	}
	for _, name := range []string{"plain", "local", "vars"} {
		if s := findServer(t, p, model.ScopeManaged, name); s.Start != model.StartNo || s.Origin.Why.IsZero() {
			t.Errorf("%s = %s (%q), want dropped with a why", name, s.Start, s.Origin.Why)
		}
	}
	if s := findServer(t, p, model.ScopeUser, "search"); s.Start != model.StartNo || !strings.Contains(s.Origin.Why.String(), "managed") {
		t.Errorf("user search = %s (%q), want overridden by the managed one", s.Start, s.Origin.Why)
	}
}

func TestManagedProvidedServersAreIgnoredOutsideManaged(t *testing.T) {
	c := fakeHome(t, map[string]string{".claude/settings.json": `{"managedMcpServers": {"x": {"type": "http", "url": "https://x.example.com"}}}`})

	if p := serversFor(t, c, model.TrustTrusted); len(p.Servers) != 0 {
		t.Errorf("servers = %v, want none from managedMcpServers in user settings", serverViews(p.Servers))
	}
}

func TestPluginServers(t *testing.T) {
	files := fmtPlugin("true")
	files[fmtRoot+"/.mcp.json"] = mcpJSON(`"lint": {"command": "${CLAUDE_PLUGIN_ROOT}/bin/lint"}, "docs": {"type": "http", "url": "https://DOCS.example.com:443/mcp/"}`)
	files[fmtRoot+"/.claude-plugin/plugin.json"] = `{"name": "fmt", "mcpServers": {"api": {"type": "http", "url": "https://api.example.com"}}}`
	files[".claude.json"] = claudeJSON(httpDocs, "", "")
	c := fakeHome(t, files)

	p := serversFor(t, c, model.TrustTrusted)

	for _, name := range []string{"lint", "api"} {
		s := findServer(t, p, model.ScopePlugin, name)
		if s.Start != model.StartYes || s.Plugin.String() != "fmt@m" {
			t.Errorf("plugin %s = %s plugin %q, want it to start from fmt@m", name, s.Start, s.Plugin)
		}
	}
	if s := findServer(t, p, model.ScopePlugin, "docs"); s.Start != model.StartNo || !strings.Contains(s.Origin.Why.String(), "same endpoint") {
		t.Errorf("plugin docs = %s (%q), want a duplicate of the user server by endpoint", s.Start, s.Origin.Why)
	}
}

func TestPluginServersOfAPluginThatsOff(t *testing.T) {
	files := fmtPlugin("false")
	files[fmtRoot+"/.mcp.json"] = mcpJSON(`"lint": {"command": "lint"}`)
	c := fakeHome(t, files)

	if p := serversFor(t, c, model.TrustTrusted); len(p.Servers) != 0 {
		t.Errorf("servers = %v, want none from a plugin that's off", serverViews(p.Servers))
	}
}

func TestReservedNamesAreSkipped(t *testing.T) {
	c := fakeHome(t, map[string]string{".claude.json": claudeJSON(`"computer-use": {"command": "x"}`, "", "")})

	if s := findServer(t, serversFor(t, c, model.TrustTrusted), model.ScopeUser, "computer-use"); s.Start != model.StartNo {
		t.Errorf("computer-use = %s, want skipped as a reserved name", s.Start)
	}
}

func TestServerSecretsAreMasked(t *testing.T) {
	const tok = "tok_ABCDEFGHIJKLMNOPQRST"
	c := fakeHome(t, map[string]string{
		".claude.json": claudeJSON(`"a": {"command": "srv", "args": ["--key", "`+tok+`"], "env": {"API_TOKEN": "`+tok+`"}},
			"b": {"type": "http", "url": "https://x.example.com/mcp?key=`+tok+`", "headers": {"Authorization": "Bearer `+tok+`"}}`, "", ""),
	})

	p := serversFor(t, c, model.TrustTrusted)

	a, b := findServer(t, p, model.ScopeUser, "a"), findServer(t, p, model.ScopeUser, "b")
	all := slices.Concat([]string{a.Args[1].String(), b.URL.String()}, texts(a.Env), texts(b.Headers))
	for _, s := range all {
		if strings.Contains(s, tok) || !strings.Contains(s, "REDACTED") {
			t.Errorf("%q isn't masked", s)
		}
	}
}

func TestBrokenClaudeJSONServersGiveAFinding(t *testing.T) {
	c := fakeHome(t, map[string]string{".claude.json": `{"mcpServers": {"a": 1}}`})
	ps := []model.Project{project(c, model.TrustTrusted)}

	fs := Adapter{}.Extensions(c, ps)

	if len(ps[0].Servers) != 0 || len(rulesOf(fs, "JARX-SCAN-002")) != 1 {
		t.Errorf("servers %v findings %v, want no server and one unreadable finding", serverViews(ps[0].Servers), fs)
	}
}

func TestEnvAndHeaderValuesAreMaskedByTheirName(t *testing.T) {
	const plain = "Xq7Lm2Pz9Rw4Tb8Nc1VdKj5Hs3Fg6Yu" // no known format, caught by its name
	c := fakeHome(t, map[string]string{
		".claude.json": claudeJSON(`"a": {"command": "srv", "env": {"API_TOKEN": "`+plain+`", "API_BASE": "https://api.example.com", "KEY_REF": "${API_KEY}"}},
			"b": {"type": "http", "url": "https://b.example.com", "headers": {"X-Api-Key": "`+plain+`"}}`, "", ""),
	})
	ps, err := catalog.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	if c.Scrub, err = redact.New(ps, nil); err != nil {
		t.Fatal(err)
	}

	p := serversFor(t, c, model.TrustTrusted)

	a, b := findServer(t, p, model.ScopeUser, "a"), findServer(t, p, model.ScopeUser, "b")
	got := strings.Join(slices.Concat(texts(a.Env), texts(b.Headers)), " ")
	if strings.Contains(got, plain) || strings.Count(got, "REDACTED") != 2 {
		t.Errorf("env and headers = %q, want both secret values masked", got)
	}
	if !strings.Contains(got, "API_BASE=https://api.example.com") || !strings.Contains(got, "KEY_REF=${API_KEY}") {
		t.Errorf("env = %q, want plain values and references kept", got)
	}
}

func TestServersCarryTheRawLaunchForProbe(t *testing.T) {
	const tok = "tok_ABCDEFGHIJKLMNOPQRST"
	files := fmtPlugin("true")
	files[fmtRoot+"/.mcp.json"] = mcpJSON(`"lint": {"command": "${CLAUDE_PLUGIN_ROOT}/bin/lint", "env": {"KEY": "` + tok + `"}}`)
	files[".claude.json"] = claudeJSON(`"remote": {"type": "http", "url": "https://r.example.com/mcp", "headers": {"Authorization": "Bearer `+tok+`"}, "oauth": {"clientId": "x"}},
		"helped": {"type": "http", "url": "https://h.example.com/mcp", "headersHelper": "get-token"}`, "", "")
	c := fakeHome(t, files)

	p := serversFor(t, c, model.TrustTrusted)

	lint, ok := findServer(t, p, model.ScopePlugin, "lint").Launch.Spec()
	if !ok || lint.Command != "${CLAUDE_PLUGIN_ROOT}/bin/lint" || lint.Env[0][1] != tok ||
		lint.PluginRoot != c.Env.MapPath("/"+fmtRoot) || lint.ProjectDir != p.Path.Raw() {
		t.Errorf("plugin launch = %+v, want the raw command, env and dirs", lint)
	}
	remote, _ := findServer(t, p, model.ScopeUser, "remote").Launch.Spec()
	if remote.URL != "https://r.example.com/mcp" || remote.Headers[0][1] != "Bearer "+tok || !remote.OAuth {
		t.Errorf("remote launch = %+v, want the raw header and the oauth flag", remote)
	}
	if helped, _ := findServer(t, p, model.ScopeUser, "helped").Launch.Spec(); !helped.HeadersHelper {
		t.Error("a headersHelper should be flagged")
	}
}
