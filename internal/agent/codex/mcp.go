package codex

import (
	"regexp"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// MCP servers, from developers.openai.com/codex/mcp, /config-reference and
// /enterprise/managed-configuration (read 2026-11-23). See "Codex MCP config
// and which servers start" in docs/design.md.
//
//   - Servers are [mcp_servers.<id>] tables in any config layer. A layer
//     that isn't loaded (an untrusted project, a profile file without
//     --profile) gives servers that don't start, with the layer's reason.
//   - enabled = false turns a server off. A server with command is stdio,
//     one with url is streamable HTTP.
//   - requirements.toml's mcp_servers is an allowlist: the id and its
//     identity must both match, and an empty table turns every server off.
//   - The docs don't say whether a higher layer's [mcp_servers.<id>]
//     replaces a lower one's or merges into it, so the highest loaded one
//     is the one in use, and a note names the fields only lower layers set.
//
// jarx only reads these. Plugin servers wait for Codex plugins.

// serverDef is one [mcp_servers.<id>] table from one layer.
type serverDef struct {
	id    string
	table map[string]any
	layer *layer
}

// servers lists every server definition for the project and decides which
// ones Codex would start.
func (e *extensions) servers() {
	var defs []serverDef
	for _, l := range e.v.layers {
		table, _ := l.raw["mcp_servers"].(map[string]any)
		for _, id := range sortedKeys(table) {
			if t, ok := table[id].(map[string]any); ok {
				defs = append(defs, serverDef{id: id, table: t, layer: l})
			}
		}
	}
	winners := map[string]int{} // id to the highest loaded definition
	for i, d := range defs {
		if _, seen := winners[d.id]; !seen && d.layer.origin.InEffect {
			winners[d.id] = i
		}
	}
	for i, d := range defs {
		e.project.Servers = append(e.project.Servers, e.server(d, defs, winners, i))
	}
	e.redefineFindings(defs, winners)
}

func (e *extensions) server(d serverDef, defs []serverDef, winners map[string]int, i int) model.Server {
	s := e.fields(d)
	var why, note string
	win, hasWin := winners[d.id]
	switch {
	case !d.layer.origin.InEffect:
		s.Start, why = model.StartNo, d.layer.origin.Why.String()
	case hasWin && win != i:
		w := defs[win]
		s.Start, why = model.StartNo, "overridden by [mcp_servers."+d.id+"] in the "+string(w.layer.origin.Scope)+
			" config; the docs don't say whether Codex merges fields from this one into it"
	case d.table["enabled"] == false:
		s.Start, why = model.StartNo, "enabled = false"
	default:
		s.Start, why, note = e.decide(d, s.Transport)
		if s.Start == model.StartYes || s.Start == model.StartMaybe {
			note = joinNotes(note, mergeNote(d, defs, i))
		}
	}
	s.Origin = d.layer.origin
	s.Origin.InEffect = s.Start == model.StartYes || s.Start == model.StartMaybe
	if !s.Origin.InEffect {
		s.Origin.Why = e.v.s.text(why)
	}
	s.Note = e.v.s.text(note)
	return s
}

// decide applies the server's shape and the requirements allowlist.
func (e *extensions) decide(d serverDef, t model.Transport) (model.StartState, string, string) {
	note := ""
	switch {
	case t == model.TransportUnknown && str(d.table, "command") == "":
		return model.StartNo, "neither command nor url is set", ""
	case t == model.TransportUnknown:
		note = "both command and url are set, and the docs don't say which one Codex uses"
	}
	switch r := e.v.s.req.allows(d, t); r {
	case matchNo:
		return model.StartNo, "not allowed by mcp_servers in requirements.toml (the id and its identity must both match)", ""
	case matchUnsettled:
		return model.StartMaybe, "", joinNotes(note, "requirements.toml's identity for it has a regex jarx couldn't compile")
	case matchYes:
	}
	if note != "" {
		return model.StartMaybe, "", note
	}
	return model.StartYes, "", ""
}

// mergeNote names the fields lower loaded layers set for the same id that
// the one in use doesn't, since they may merge in.
func mergeNote(d serverDef, defs []serverDef, i int) string {
	var extra []string
	for _, o := range defs[i+1:] {
		if o.id != d.id || !o.layer.origin.InEffect {
			continue
		}
		for _, k := range sortedKeys(o.table) {
			if _, ok := d.table[k]; !ok && !slices.Contains(extra, k) {
				extra = append(extra, k)
			}
		}
	}
	if len(extra) == 0 {
		return ""
	}
	return "a lower layer also sets " + strings.Join(extra, ", ") + " for this server; the docs don't say whether Codex merges them in"
}

func joinNotes(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "; " + b
}

// fields copies a server table into the model, scrubbed.
func (e *extensions) fields(d serverDef) model.Server {
	t, sc := d.table, e.v.s.c.Scrub
	text := e.v.s.text
	s := model.Server{
		Name: text(d.id), Transport: codexTransport(t), Command: text(str(t, "command")), URL: text(str(t, "url")),
		Cwd: text(str(t, "cwd")), BearerVar: text(str(t, "bearer_token_env_var")), Auth: text(str(t, "auth")),
		HeadersHelper: text(str(t, "http_headers_helper")),
	}
	for _, a := range strList(t, "args") {
		s.Args = append(s.Args, text(a))
	}
	env, _ := t["env"].(map[string]any)
	for _, k := range sortedKeys(env) {
		s.Env = append(s.Env, agent.Pair(sc, k, scalar(env[k])))
	}
	headers, _ := t["http_headers"].(map[string]any)
	for _, k := range sortedKeys(headers) {
		s.Headers = append(s.Headers, agent.Pair(sc, k, scalar(headers[k])))
	}
	vars, _ := t["env_http_headers"].(map[string]any)
	for _, k := range sortedKeys(vars) {
		s.HeaderVars = append(s.HeaderVars, model.Pair{Key: text(k), Value: text(scalar(vars[k]))}) // the value is a var name
	}
	s.ForwardEnv = forwardEnv(t, text)
	if _, ok := t["enabled_tools"]; ok {
		s.EnabledTools = texts(strList(t, "enabled_tools"), text)
	}
	s.DisabledTools = texts(strList(t, "disabled_tools"), text)
	s.Approvals = approvals(t, text)
	s.Launch = launch(t)
	return s
}

// launch is the raw launch data probe needs. Codex doesn't expand ${VAR} in
// config, so values are used as written; env vars come in through env_vars,
// bearer_token_env_var and env_http_headers.
func launch(t map[string]any) model.Launch {
	spec := model.LaunchSpec{
		Command: str(t, "command"), Args: strList(t, "args"), URL: str(t, "url"), Cwd: str(t, "cwd"),
		BearerVar: str(t, "bearer_token_env_var"), HeadersHelper: str(t, "http_headers_helper") != "",
		Env: rawPairs(t, "env"), Headers: rawPairs(t, "http_headers"), HeaderVars: rawPairs(t, "env_http_headers"),
	}
	switch str(t, "auth") {
	case "oauth", "chatgpt":
		spec.OAuth = true
	}
	list, _ := t["env_vars"].([]any)
	for _, v := range list {
		switch v := v.(type) {
		case string:
			spec.ForwardEnv = append(spec.ForwardEnv, model.ForwardVar{Name: v})
		case map[string]any:
			spec.ForwardEnv = append(spec.ForwardEnv, model.ForwardVar{Name: str(v, "name"), Remote: str(v, "source") == "remote"})
		}
	}
	return model.NewLaunch(spec)
}

// rawPairs is a table of strings, sorted by key.
func rawPairs(t map[string]any, key string) [][2]string {
	m, _ := t[key].(map[string]any)
	out := make([][2]string, 0, len(m))
	for _, k := range sortedKeys(m) {
		out = append(out, [2]string{k, scalar(m[k])})
	}
	return out
}

func codexTransport(t map[string]any) model.Transport {
	cmd, url := str(t, "command"), str(t, "url")
	switch {
	case cmd != "" && url == "":
		return model.TransportStdio
	case url != "" && cmd == "":
		return model.TransportHTTP
	}
	return model.TransportUnknown
}

// forwardEnv is env_vars: plain names, or tables with a name and a source.
// A remote source is shown after the name.
func forwardEnv(t map[string]any, text func(string) redact.Text) []redact.Text {
	list, _ := t["env_vars"].([]any)
	var out []redact.Text
	for _, v := range list {
		switch v := v.(type) {
		case string:
			out = append(out, text(v))
		case map[string]any:
			name := str(v, "name")
			if src := str(v, "source"); src != "" && src != "local" {
				name += " (" + src + ")"
			}
			out = append(out, text(name))
		}
	}
	return out
}

// approvals is the server's default approval mode under the empty key, then
// each tool's.
func approvals(t map[string]any, text func(string) redact.Text) []model.Pair {
	var out []model.Pair
	if m := str(t, "default_tools_approval_mode"); m != "" {
		out = append(out, model.Pair{Key: text(""), Value: text(m)})
	}
	tools, _ := t["tools"].(map[string]any)
	for _, name := range sortedKeys(tools) {
		tool, _ := tools[name].(map[string]any)
		if m := str(tool, "approval_mode"); m != "" {
			out = append(out, model.Pair{Key: text(name), Value: text(m)})
		}
	}
	return out
}

func texts(ss []string, text func(string) redact.Text) []redact.Text {
	out := make([]redact.Text, 0, len(ss))
	for _, s := range ss {
		out = append(out, text(s))
	}
	return out
}

func str(t map[string]any, key string) string {
	s, _ := t[key].(string)
	return s
}

func strList(t map[string]any, key string) []string {
	list, _ := t[key].([]any)
	out := make([]string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

type matchResult int

const (
	matchNo matchResult = iota
	matchYes
	matchUnsettled // a regex jarx can't compile
)

// allows applies the mcp_servers allowlist in requirements.toml. With no
// list, every server is allowed; with an empty one, none is.
func (r *requirements) allows(d serverDef, t model.Transport) matchResult {
	if r == nil {
		return matchYes
	}
	list, ok := r.raw["mcp_servers"].(map[string]any)
	if !ok {
		return matchYes
	}
	entry, _ := list[d.id].(map[string]any)
	identity, _ := entry["identity"].(map[string]any)
	switch t {
	case model.TransportStdio:
		return commandMatches(identity["command"], str(d.table, "command"), strList(d.table, "args"))
	case model.TransportHTTP:
		return valueMatches(identity["url"], str(d.table, "url"))
	case model.TransportSSE, model.TransportWS, model.TransportUnknown:
	}
	return matchNo
}

// commandMatches checks identity.command: a string matches the command
// alone; a table needs the exact executable and one matcher per argument.
func commandMatches(rule any, command string, args []string) matchResult {
	switch rule := rule.(type) {
	case string:
		return boolMatch(rule == command)
	case map[string]any:
		matchers, _ := rule["args"].([]any)
		if str(rule, "executable") != command || len(matchers) != len(args) {
			return matchNo
		}
		result := matchYes
		for i, m := range matchers {
			switch valueMatches(m, args[i]) {
			case matchNo:
				return matchNo
			case matchUnsettled:
				result = matchUnsettled
			case matchYes:
			}
		}
		return result
	}
	return matchNo
}

// valueMatches checks a string rule (exact) or a matcher table with exact,
// prefix or a regex that has to match the whole value.
func valueMatches(rule any, value string) matchResult {
	switch rule := rule.(type) {
	case string:
		return boolMatch(rule == value)
	case map[string]any:
		switch str(rule, "match") {
		case "exact":
			return boolMatch(str(rule, "value") == value)
		case "prefix":
			return boolMatch(strings.HasPrefix(value, str(rule, "value")))
		case "regex":
			re, err := regexp.Compile(`^(?:` + str(rule, "expression") + `)$`)
			if err != nil {
				return matchUnsettled
			}
			return boolMatch(re.MatchString(value))
		}
	}
	return matchNo
}

func boolMatch(b bool) matchResult {
	if b {
		return matchYes
	}
	return matchNo
}

// RepoRedefinesServerToken is a trusted repository's [mcp_servers.<id>]
// that redefines one of your servers while your layer sends it a credential
// the repository's doesn't set. If Codex merges the tables, your token goes
// to wherever the repository points the server.
func RepoRedefinesServerToken() finding.Rule {
	return finding.Rule{
		ID: "JARX-CODEX-009", Severity: finding.High, Title: "A repo can redirect your server's token",
		Detail: "a trusted repository's .codex/config.toml redefines one of your MCP servers, and your own config sends that server a credential the repository's version doesn't set. The docs don't say whether Codex merges the two. If it does, your credential goes to the URL or command the repository picked.",
		Fix:    "rename your server, or drop the repository's [mcp_servers] entry. Check where the server points before you trust the project.",
	}
}

// RepoRedefinesServer is the same with no credential involved: the
// repository's server takes your server's id, and the tool approval settings
// you keyed on it.
func RepoRedefinesServer() finding.Rule {
	return finding.Rule{
		ID: "JARX-CODEX-010", Severity: finding.Medium, Title: "A repo redefines one of your MCP servers",
		Detail: "a trusted repository's .codex/config.toml defines an MCP server with the id of one of yours, so Codex uses the repository's definition there",
		Fix:    "rename your server, or drop the repository's [mcp_servers] entry",
	}
}

// credentialKeys are the server fields that send a credential.
//
//nolint:gochecknoglobals // fixed list, read only
var credentialKeys = []string{"bearer_token_env_var", "env_http_headers", "http_headers", "env"}

// yourCredentials says whether one of your loaded layers below the
// repository's server defines the same id, and which credential fields it
// sets that the repository's doesn't.
func yourCredentials(repo serverDef, lower []serverDef) (bool, []string) {
	mine := false
	var keys []string
	for _, d := range lower {
		if d.id != repo.id || !d.layer.origin.InEffect || d.layer.origin.Scope == model.ScopeProject {
			continue
		}
		mine = true
		for _, k := range credentialKeys {
			_, set := d.table[k]
			_, repoSets := repo.table[k]
			if set && !repoSets && !slices.Contains(keys, k) {
				keys = append(keys, k)
			}
		}
	}
	return mine, keys
}

// redefineFindings flags a trusted repository's server that wins over one
// of your own with the same id.
func (e *extensions) redefineFindings(defs []serverDef, winners map[string]int) {
	for _, id := range sortedKeys(winners) {
		w := defs[winners[id]]
		if w.layer.origin.Scope != model.ScopeProject {
			continue
		}
		mine, yours := yourCredentials(w, defs[winners[id]+1:])
		switch {
		case len(yours) > 0:
			e.findings = append(e.findings, RepoRedefinesServerToken().New(w.layer.origin, e.v.s.text(
				"the repository redefines mcp_servers."+id+", and your config sets "+strings.Join(yours, ", ")+" for it")))
		case mine:
			e.findings = append(e.findings, RepoRedefinesServer().New(w.layer.origin, e.v.s.text(
				"the repository redefines mcp_servers."+id+", one of your servers")))
		}
	}
}
