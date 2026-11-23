package claude

import (
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
)

// MCP servers, from code.claude.com/docs/en/mcp and /managed-mcp (read
// 2026-11-23). See "Claude MCP config and which servers start" in
// docs/design.md for the rules this file follows.
//
//   - User servers are the top-level mcpServers in ~/.claude.json, local
//     ones are projects["<path>"].mcpServers there, project ones are the
//     project's .mcp.json, and plugin ones are a loaded plugin's .mcp.json
//     or plugin.json mcpServers. Managed ones are managed-mcp.json and the
//     managedMcpServers key in managed settings.
//   - jarx only reads these. It never starts a server here; probe decides
//     that later, only for servers marked StartYes or StartMaybe.

const (
	jsonNull = "null"
	typeHTTP = "http" // a server type, a hook type and a URL scheme
)

// rawServer is one server entry as written. Strings stay raw until they go
// into the model, where they're scrubbed, like hooks.
type rawServer struct {
	name, typ, command, url, helper string
	args                            []string
	env, headers                    [][2]string
	// vars says whether a ${VAR} reference appears outside env.
	vars bool
	// extra is the keys a managedMcpServers entry may not have.
	extra []string
}

// serverEntry is the part of an entry jarx decodes.
type serverEntry struct {
	Type          *string           `json:"type"`
	Command       *string           `json:"command"`
	Args          []string          `json:"args"`
	URL           *string           `json:"url"`
	Env           map[string]string `json:"env"`
	Headers       map[string]string `json:"headers"`
	HeadersHelper *string           `json:"headersHelper"`
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// parseServers decodes an mcpServers object. Entries that aren't objects
// with the documented field types are skipped, each with a problem.
func parseServers(raw json.RawMessage, problem func(string)) []rawServer {
	if len(raw) == 0 || string(raw) == jsonNull {
		return nil
	}
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		problem("mcpServers isn't a JSON object, skipped")
		return nil
	}
	out := make([]rawServer, 0, len(entries))
	for _, name := range sortedKeys(entries) {
		s, ok := parseServer(name, entries[name])
		if !ok {
			problem("an entry in mcpServers isn't a server object, skipped")
			continue
		}
		out = append(out, s)
	}
	return out
}

func parseServer(name string, raw json.RawMessage) (rawServer, bool) {
	var e serverEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return rawServer{}, false
	}
	var keys map[string]json.RawMessage
	_ = json.Unmarshal(raw, &keys)
	s := rawServer{
		name: name, typ: deref(e.Type), command: deref(e.Command), url: deref(e.URL),
		helper: deref(e.HeadersHelper), args: e.Args, env: pairs(e.Env), headers: pairs(e.Headers),
	}
	for _, k := range []string{"command", "args", "env", "headersHelper"} {
		if _, ok := keys[k]; ok {
			s.extra = append(s.extra, k)
		}
	}
	s.vars = usesVars(s)
	return s, true
}

// usesVars says whether a ${VAR} reference appears outside env.
func usesVars(s rawServer) bool {
	return hasVar(s.command) || hasVar(s.url) || hasVar(s.helper) || slices.ContainsFunc(s.args, hasVar) ||
		slices.ContainsFunc(s.headers, func(p [2]string) bool { return hasVar(p[0]) || hasVar(p[1]) })
}

func pairs(m map[string]string) [][2]string {
	out := make([][2]string, 0, len(m))
	for _, k := range sortedKeys(m) {
		out = append(out, [2]string{k, m[k]})
	}
	return out
}

func hasVar(s string) bool { return strings.Contains(s, "${") }

// transport maps a type as written to the model's transport. An entry with
// no type is stdio, Claude's default.
func transport(typ string) model.Transport {
	switch typ {
	case "", "stdio":
		return model.TransportStdio
	case typeHTTP, "streamable-http":
		return model.TransportHTTP
	case "sse":
		return model.TransportSSE
	case "ws":
		return model.TransportWS
	}
	return model.TransportUnknown
}

func remote(t model.Transport) bool {
	return t == model.TransportHTTP || t == model.TransportSSE || t == model.TransportWS
}

// claudeMCP is what jarx keeps from ~/.claude.json for MCP: the user
// servers and, per project path, its local servers and its
// disabledMcpServers list.
type claudeMCP struct {
	user     []rawServer
	projects map[string]projectMCP
	origin   model.Origin
}

type projectMCP struct {
	servers  []rawServer
	disabled []string
}

// readClaudeMCP streams ~/.claude.json and keeps only the MCP keys. A file
// that's missing or isn't valid JSON gives nothing here: Projects already
// reports a file it can't read.
func readClaudeMCP(c agent.Context, problem func(model.Origin, string)) claudeMCP {
	file := configFile(c.Env)
	out := claudeMCP{
		projects: map[string]projectMCP{},
		origin:   model.Origin{Agent: model.AgentClaude, File: model.NewPath(c.Scrub, file), Scope: model.ScopeUser, InEffect: true},
	}
	r, err := c.Files.Open(file)
	if err != nil {
		return out
	}
	defer func() { _ = r.Close() }()
	j := jsonReader{dec: json.NewDecoder(&capReader{r: r, left: maxConfigSize})}
	var user json.RawMessage
	projects := map[string]map[string]json.RawMessage{}
	if j.mcpTop(&user, projects) != nil {
		return out
	}
	say := func(s string) { problem(out.origin, s) }
	out.user = parseServers(user, say)
	for path, keys := range projects {
		pm := projectMCP{servers: parseServers(keys["mcpServers"], say)}
		if raw, ok := keys["disabledMcpServers"]; ok && json.Unmarshal(raw, &pm.disabled) != nil {
			say("disabledMcpServers isn't a list of strings, skipped")
		}
		out.projects[c.Env.MapPath(path)] = pm
	}
	return out
}

// mcpTop reads the top-level object, keeping mcpServers and the MCP keys of
// each project entry. Every other value is read past and dropped.
func (j jsonReader) mcpTop(user *json.RawMessage, projects map[string]map[string]json.RawMessage) error {
	if err := j.expect('{', "the file isn't a JSON object"); err != nil {
		return err
	}
	for j.dec.More() {
		key, err := j.key()
		if err != nil {
			return err
		}
		switch key {
		case "mcpServers":
			err = j.dec.Decode(user)
		case "projects":
			err = j.mcpProjects(projects)
		default:
			err = j.skip()
		}
		if err != nil {
			return j.readErr(err)
		}
	}
	return j.expect('}', "the file isn't closed")
}

func (j jsonReader) mcpProjects(out map[string]map[string]json.RawMessage) error {
	if err := j.expect('{', "projects isn't a JSON object"); err != nil {
		return err
	}
	for j.dec.More() {
		path, err := j.key()
		if err != nil {
			return err
		}
		keys, err := j.mcpEntry()
		if err != nil {
			return err
		}
		if keys != nil {
			out[path] = keys
		}
	}
	return j.expect('}', "object isn't closed")
}

// mcpEntry reads one project entry and keeps its MCP keys. A value that
// isn't an object is dropped and gives nil.
func (j jsonReader) mcpEntry() (map[string]json.RawMessage, error) {
	tok, err := j.dec.Token()
	if err != nil {
		return nil, j.readErr(err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, j.dropRest(tok)
	}
	keys := map[string]json.RawMessage{}
	for j.dec.More() {
		k, err := j.key()
		if err != nil {
			return nil, err
		}
		if k == "mcpServers" || k == "disabledMcpServers" {
			var raw json.RawMessage
			err = j.dec.Decode(&raw)
			keys[k] = raw
		} else {
			err = j.skip()
		}
		if err != nil {
			return nil, j.readErr(err)
		}
	}
	return keys, j.expect('}', "object isn't closed")
}

// managedFile is managed-mcp.json as jarx found it.
type managedFile struct {
	state   managedFileState
	servers []rawServer
	origin  model.Origin
}

type managedFileState int

const (
	fileAbsent managedFileState = iota
	fileOK
	fileBroken
)

// readManagedMCP reads managed-mcp.json from the managed dir.
func readManagedMCP(c agent.Context, problem func(model.Origin, string)) managedFile {
	dir := managedDir(c.Env)
	if dir == "" {
		return managedFile{}
	}
	path := filepath.Join(dir, "managed-mcp.json")
	m := managedFile{origin: model.Origin{Agent: model.AgentClaude, File: model.NewPath(c.Scrub, path), Scope: model.ScopeManaged, InEffect: true}}
	data, err := c.Files.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return m
	case err != nil:
		m.state = fileBroken
		problem(m.origin, "couldn't read the file")
		return m
	}
	var top struct {
		MCPServers json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &top); err != nil {
		m.state = fileBroken
		problem(m.origin, jsonProblem(data, err))
		return m
	}
	m.state = fileOK
	m.servers = parseServers(top.MCPServers, func(s string) { problem(m.origin, s) })
	return m
}

// projectServers reads the project's .mcp.json.
func (e *extReader) projectServers() ([]rawServer, model.Origin) {
	path := filepath.Join(e.project.Path.Raw(), ".mcp.json")
	o := model.Origin{Agent: model.AgentClaude, File: model.NewPath(e.c.Scrub, path), Scope: model.ScopeProject, InEffect: true}
	status, data := (&reader{c: e.c}).read(path)
	if status == model.ReadMissing {
		return nil, o
	}
	var top struct {
		MCPServers json.RawMessage `json:"mcpServers"`
	}
	if status != model.ReadOK {
		e.problem(o, "couldn't read the file")
		return nil, o
	}
	if err := json.Unmarshal(data, &top); err != nil {
		e.problem(o, jsonProblem(data, err))
		return nil, o
	}
	e.project.Configs = append(e.project.Configs, model.Config{Origin: o, Text: e.text(string(data))})
	return parseServers(top.MCPServers, func(s string) { e.problem(o, s) }), o
}

// pluginServers reads the MCP servers of every plugin Claude loads here.
func (e *extReader) pluginServers() []def {
	var out []def
	for _, pl := range e.project.Plugins {
		if pl.Origin.InEffect && !pl.Path.IsZero() {
			out = append(out, e.onePluginServers(pl)...)
		}
	}
	return out
}

// onePluginServers reads one plugin's servers: the plugin root's .mcp.json
// and plugin.json's mcpServers, inline or as paths inside the plugin.
func (e *extReader) onePluginServers(pl model.Plugin) []def {
	root := pl.Path.Raw()
	var m struct {
		Name       string          `json:"name"`
		MCPServers json.RawMessage `json:"mcpServers"`
	}
	manifestPath := filepath.Join(root, ".claude-plugin", "plugin.json")
	if status, data := (&reader{c: e.c}).read(manifestPath); status == model.ReadOK {
		_ = json.Unmarshal(data, &m)
	}
	files := []string{filepath.Join(root, ".mcp.json")}
	declared := paths(m.MCPServers)
	for _, f := range declared {
		if full := inRoot(root, f); full != "" && !slices.Contains(files, full) {
			files = append(files, full)
		}
	}
	var out []def
	add := func(o model.Origin, ss []rawServer) {
		for _, s := range ss {
			out = append(out, def{raw: s, origin: o, rank: rankPlugin, plugin: pl.ID.String(), pluginName: m.Name})
		}
	}
	for _, f := range files {
		o := pluginOrigin(e, f)
		if status, data := (&reader{c: e.c}).read(f); status == model.ReadOK {
			add(o, e.serversFile(o, data))
		}
	}
	if len(declared) == 0 && len(m.MCPServers) > 0 {
		o := pluginOrigin(e, manifestPath)
		add(o, parseServers(m.MCPServers, func(s string) { e.problem(o, s) }))
	}
	return out
}

func pluginOrigin(e *extReader, file string) model.Origin {
	return model.Origin{Agent: model.AgentClaude, File: model.NewPath(e.c.Scrub, file), Scope: model.ScopePlugin, InEffect: true}
}

// serversFile reads the mcpServers of a file shaped like .mcp.json.
func (e *extReader) serversFile(o model.Origin, data []byte) []rawServer {
	var top struct {
		MCPServers json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &top); err != nil {
		e.problem(o, jsonProblem(data, err))
		return nil
	}
	return parseServers(top.MCPServers, func(s string) { e.problem(o, s) })
}

func (e *extReader) problem(o model.Origin, why string) {
	e.findings = append(e.findings, finding.UnreadableRecord().New(o, e.text(why)))
}

// mcpShared is what every project's MCP decision reads: ~/.claude.json and
// managed-mcp.json, read once per scan.
type mcpShared struct {
	claude  claudeMCP
	managed managedFile
}

func loadMCPShared(c agent.Context, problem func(model.Origin, string)) mcpShared {
	return mcpShared{claude: readClaudeMCP(c, problem), managed: readManagedMCP(c, problem)}
}

// servers collects every server definition for the project, decides which
// ones Claude would start, and stores them on the project.
func (e *extReader) servers(sh mcpShared) {
	var defs []def
	addAll := func(ss []rawServer, o model.Origin, rank int) {
		for _, s := range ss {
			defs = append(defs, def{raw: s, origin: o, rank: rank})
		}
	}
	addAll(sh.managed.servers, sh.managed.origin, rankManagedFile)
	defs = append(defs, e.managedProvided()...)
	local := sh.claude.projects[e.project.Path.Raw()]
	localOrigin := sh.claude.origin
	localOrigin.Scope = model.ScopeLocal
	addAll(local.servers, localOrigin, rankLocal)
	proj, projOrigin := e.projectServers()
	addAll(proj, projOrigin, rankProject)
	addAll(sh.claude.user, sh.claude.origin, rankUser)
	defs = append(defs, e.pluginServers()...)

	pol := e.mcpPolicy(sh, local.disabled)
	pol.decide(defs)
	for _, d := range defs {
		e.project.Servers = append(e.project.Servers, e.toModel(d))
	}
}

// managedProvided is the managedMcpServers entries from the managed sources
// in use, highest first. Claude never reads the key from HKCU. A name a
// higher source already defines is left out, since its entry applies whole.
func (e *extReader) managedProvided() []def {
	var out []def
	seen := map[string]bool{}
	for _, l := range e.managedLayers() {
		if !l.origin.InEffect || l.hkcu || len(l.managedServers) == 0 {
			continue
		}
		for _, s := range parseServers(l.managedServers, func(why string) { e.problem(l.origin, why) }) {
			if seen[s.name] {
				continue
			}
			seen[s.name] = true
			out = append(out, def{raw: s, origin: l.origin, rank: rankManagedSettings})
		}
	}
	return out
}

func (e *extReader) toModel(d def) model.Server {
	s := model.Server{
		Name: e.text(d.raw.name), Transport: transport(d.raw.typ), Command: e.text(d.raw.command), URL: e.text(d.raw.url),
		HeadersHelper: e.text(d.raw.helper), Plugin: e.text(d.plugin), Start: d.start, Note: e.text(d.note), Origin: d.origin,
	}
	for _, a := range d.raw.args {
		s.Args = append(s.Args, e.text(a))
	}
	for _, p := range d.raw.env {
		s.Env = append(s.Env, model.Pair{Key: e.text(p[0]), Value: e.text(p[1])})
	}
	for _, p := range d.raw.headers {
		s.Headers = append(s.Headers, model.Pair{Key: e.text(p[0]), Value: e.text(p[1])})
	}
	s.Origin.InEffect = d.start == model.StartYes || d.start == model.StartMaybe
	if !s.Origin.InEffect {
		s.Origin.Why = e.text(d.why)
	}
	return s
}

// mcpKey reads the MCP keys a settings file may set: approvals and the
// allow and deny lists from any file, the rest from managed settings.
func (r *layerReader) mcpKey(key string, raw json.RawMessage) {
	switch key {
	case keyAllProjectMCP:
		var v bool
		if json.Unmarshal(raw, &v) == nil {
			r.l.mcpEnableAll = &v
		}
	case "enabledMcpjsonServers":
		r.l.mcpEnabled = r.rawStrings(key, raw)
	case "disabledMcpjsonServers":
		r.l.mcpRejected = r.rawStrings(key, raw)
	case "allowedMcpServers":
		if list := r.policyList(key, raw); list != nil {
			r.l.mcpAllow = &list
		}
	case "deniedMcpServers":
		r.l.mcpDeny = r.policyList(key, raw)
	default:
		r.managedMCPKey(key, raw)
	}
}

// managedMCPKey reads the MCP keys Claude takes from managed settings only.
// keyAllowed already keeps them out of other files.
func (r *layerReader) managedMCPKey(key string, raw json.RawMessage) {
	switch key {
	case "allowManagedMcpServersOnly":
		var v bool
		if err := json.Unmarshal(raw, &v); err != nil {
			r.problem(key + " isn't a bool, skipped")
			return
		}
		r.l.mcpManagedOnly = &v
	case "strictPluginOnlyCustomization":
		var all bool
		var some []string
		r.l.mcpStrict = (json.Unmarshal(raw, &all) == nil && all) ||
			(json.Unmarshal(raw, &some) == nil && slices.Contains(some, "mcp"))
	case "managedMcpServers":
		r.l.managedServers = raw
	}
}

// rawStrings decodes a list of strings without scrubbing them, for names
// jarx only compares.
func (r *layerReader) rawStrings(key string, raw json.RawMessage) []string {
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		r.problem(key + " isn't a list of strings, skipped")
		return nil
	}
	return out
}

// policyList decodes allowedMcpServers or deniedMcpServers. An entry with
// none of the three keys, or more than one, is skipped with a problem. A
// value that isn't a list is nil: the list counts as unset.
func (r *layerReader) policyList(key string, raw json.RawMessage) []policyEntry {
	var items []struct {
		Name    *string  `json:"serverName"`
		Command []string `json:"serverCommand"`
		URL     *string  `json:"serverUrl"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		r.problem(key + " isn't a list of entries, skipped")
		return nil
	}
	out := []policyEntry{}
	bad := false
	for _, it := range items {
		set := 0
		for _, on := range []bool{it.Name != nil, it.Command != nil, it.URL != nil} {
			if on {
				set++
			}
		}
		if set != 1 {
			bad = true
			continue
		}
		out = append(out, policyEntry{name: it.Name, command: it.Command, url: it.URL})
	}
	if bad {
		r.problem(key + " has entries without exactly one of serverName, serverCommand or serverUrl, skipped")
	}
	return out
}
