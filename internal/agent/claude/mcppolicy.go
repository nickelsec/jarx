package claude

import (
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/model"
)

// Which servers Claude starts, in the order the managed-mcp page gives:
// exclusive control by managed-mcp.json, then the denylist, then the
// allowlist, plus .mcp.json approval, the per-project /mcp toggles and the
// same-name precedence from the mcp page. Where the docs leave a case open,
// the server is StartMaybe with a note, never StartNo.

// Ranks for a name clash, best first. Plugins come last and are matched by
// endpoint, not by name.
const (
	rankManagedFile = iota
	rankManagedSettings
	rankLocal
	rankProject
	rankUser
	rankPlugin
)

// def is one server definition while it's being decided.
type def struct {
	raw        rawServer
	origin     model.Origin
	rank       int
	plugin     string // plugin id
	pluginName string // the name in plugin.json, for its scoped name
	start      model.StartState
	why, note  string
}

func (d *def) set(start model.StartState, why string) {
	d.start, d.why = start, why
}

// maybe marks an otherwise starting server as one the docs leave open.
func (d *def) maybe(note string) {
	if d.start == model.StartYes {
		d.start = model.StartMaybe
	}
	if d.start == model.StartMaybe && d.note == "" {
		d.note = note
	}
}

func (d *def) starts() bool { return d.start == model.StartYes || d.start == model.StartMaybe }

// scopedName is the name a plugin server registers under, or the name.
func (d *def) scopedName() string {
	if d.plugin == "" {
		return d.raw.name
	}
	name := d.pluginName
	if name == "" {
		name, _, _ = strings.Cut(d.plugin, "@")
	}
	return "plugin:" + name + ":" + d.raw.name
}

// reservedNames are the names Claude keeps for its built-in servers and
// skips in a config.
//
//nolint:gochecknoglobals // fixed list, read only
var reservedNames = []string{"workspace", "claude-in-chrome", "computer-use", "Claude Preview", "Claude Browser"}

// policyEntry is one allowedMcpServers or deniedMcpServers entry.
type policyEntry struct {
	name    *string
	command []string
	url     *string
}

// mcpPolicy is what decides every server in one project.
type mcpPolicy struct {
	exclusive managedFileState
	strict    bool // strictPluginOnlyCustomization locks mcp
	// approval of .mcp.json servers
	enableAll        bool
	enableAllSet     bool
	approved         map[string]bool
	approvalWaits    string // why an approval in a repo file doesn't count yet
	rejected         map[string]bool
	panelOff         map[string]bool
	deny             []policyEntry
	allow            []policyEntry
	allowSet         bool
	managedAllowOnly bool
}

// mcpPolicy builds the policy for the project from its settings layers.
func (e *extReader) mcpPolicy(sh mcpShared, panelOff []string) mcpPolicy {
	p := mcpPolicy{exclusive: sh.managed.state, approved: map[string]bool{}, rejected: map[string]bool{}, panelOff: map[string]bool{}}
	for _, n := range panelOff {
		p.panelOff[n] = true
	}
	waits := trustWhy(*e.project)
	home := configHome(e.c.Env, e.project.Path.Raw())
	for _, l := range e.layers {
		if l == nil {
			continue
		}
		p.crossSource(l)
		if l.origin.InEffect {
			p.fromLayer(l, approvalCounts(l.origin.Scope, waits, home), waits)
		}
	}
	p.allow, p.allowSet = e.allowlist(p.managedAllowOnly)
	return p
}

// crossSource reads the denylist and the managed-only lock, which Claude
// takes from every admin source, in effect or not.
func (p *mcpPolicy) crossSource(l *layer) {
	admin := l.origin.Scope == model.ScopeManaged && !l.hkcu
	if !l.origin.InEffect && !admin {
		return
	}
	p.deny = append(p.deny, l.mcpDeny...)
	if l.origin.Scope == model.ScopeManaged && l.mcpManagedOnly != nil && *l.mcpManagedOnly {
		p.managedAllowOnly = true
	}
}

// fromLayer reads one in-effect layer's lock, rejections and approvals.
func (p *mcpPolicy) fromLayer(l *layer, counts bool, waits string) {
	if l.origin.Scope == model.ScopeManaged && l.mcpStrict {
		p.strict = true
	}
	for _, n := range l.mcpRejected {
		p.rejected[n] = true
	}
	if !counts {
		if approves(l) {
			p.approvalWaits = "the " + string(l.origin.Scope) + " settings approve it, but that " + waits
		}
		return
	}
	if l.mcpEnableAll != nil && !p.enableAllSet {
		p.enableAll, p.enableAllSet = *l.mcpEnableAll, true
	}
	for _, n := range l.mcpEnabled {
		p.approved[n] = true
	}
}

// approvalCounts says whether a file's .mcp.json approvals count yet: a
// project file's once the folder is trusted, and a local file's then too,
// unless the folder is the config home.
func approvalCounts(s model.Scope, waits string, home bool) bool {
	if s == model.ScopeProject {
		return waits == ""
	}
	if s == model.ScopeLocal {
		return waits == "" || home
	}
	return true
}

// allowlist merges allowedMcpServers. With the managed-only lock it's the
// list from the highest admin source that sets one; without it, every
// in-effect file's list combines.
func (e *extReader) allowlist(managedOnly bool) ([]policyEntry, bool) {
	var out []policyEntry
	set := false
	for _, l := range e.layers {
		if l == nil || l.mcpAllow == nil {
			continue
		}
		if managedOnly {
			if l.origin.Scope == model.ScopeManaged && !l.hkcu {
				return *l.mcpAllow, true
			}
			continue
		}
		if l.origin.InEffect {
			out, set = append(out, *l.mcpAllow...), true
		}
	}
	return out, set
}

// decide sets every definition's start state.
func (p *mcpPolicy) decide(defs []def) {
	for i := range defs {
		defs[i].start = model.StartYes
		p.decideOne(&defs[i])
	}
	clashByName(defs)
	clashByEndpoint(defs)
}

func (p *mcpPolicy) decideOne(d *def) {
	if !p.loads(d) {
		return
	}
	if d.rank == rankProject && !p.approve(d) {
		return
	}
	if d.rank != rankProject && (p.panelOff[d.raw.name] || p.panelOff[d.scopedName()]) {
		d.set(model.StartNo, "turned off for this project in /mcp (disabledMcpServers in ~/.claude.json)")
		return
	}
	if p.checkDeny(d) {
		p.checkAllow(d)
	}
}

// loads applies what decides whether Claude reads the entry at all: its
// shape, the managed source rules and, for managedMcpServers, the entry
// checks.
func (p *mcpPolicy) loads(d *def) bool {
	if why := unusable(d.raw); why != "" {
		d.set(model.StartNo, why)
		return false
	}
	if !p.sourceAllows(d) {
		return false
	}
	if d.rank != rankManagedSettings {
		return true
	}
	if why := providedProblem(d.raw); why != "" {
		d.set(model.StartNo, "Claude drops this managedMcpServers entry: "+why)
		return false
	}
	return true
}

// unusable says why Claude can't use an entry at all, or "".
func unusable(s rawServer) string {
	t := transport(s.typ)
	switch {
	case t == model.TransportUnknown:
		return "Claude doesn't know the server type " + s.typ
	case t == model.TransportStdio && s.command == "":
		return "a stdio server with no command"
	case remote(t) && s.url == "":
		return "no URL configured, so Claude doesn't connect to it"
	case slices.Contains(reservedNames, s.name):
		return "the name is reserved for one of Claude's built-in servers, so Claude skips it"
	}
	return ""
}

// sourceAllows applies managed-mcp.json's exclusive control and the
// strictPluginOnlyCustomization lock.
func (p *mcpPolicy) sourceAllows(d *def) bool {
	managed := d.rank == rankManagedFile || d.rank == rankManagedSettings
	switch {
	case managed:
	case p.exclusive == fileOK:
		d.set(model.StartNo, "managed-mcp.json has exclusive control, so only its servers and managedMcpServers load")
		return false
	case p.exclusive == fileBroken:
		d.maybe("managed-mcp.json is there but jarx couldn't read it; if Claude can, it has exclusive control and this server doesn't load")
	}
	if p.strict && d.rank != rankPlugin && !managed {
		d.set(model.StartNo, "strictPluginOnlyCustomization locks mcp in managed settings, so Claude doesn't load servers from ~/.claude.json or .mcp.json")
		return false
	}
	return true
}

// approve applies .mcp.json approval: a rejection anywhere wins, then an
// approval from a file that counts.
func (p *mcpPolicy) approve(d *def) bool {
	switch {
	case p.rejected[d.raw.name]:
		d.set(model.StartNo, "rejected by disabledMcpjsonServers in settings")
		return false
	case p.enableAll || p.approved[d.raw.name]:
		return true
	case p.approvalWaits != "":
		d.set(model.StartUnknown, "not probed: "+p.approvalWaits)
	default:
		d.set(model.StartUnknown, "not probed: no settings file approves it, and Claude asks before using it in an interactive session")
	}
	return false
}

// checkDeny applies the denylist and says whether the server is still in.
func (p *mcpPolicy) checkDeny(d *def) bool {
	unsettled := false
	for _, en := range p.deny {
		r := matchEntry(en, d.raw)
		if r == matchYes {
			d.set(model.StartNo, "blocked by deniedMcpServers")
			return false
		}
		unsettled = unsettled || r == matchUnsettled
	}
	if unsettled {
		d.maybe("a deniedMcpServers entry uses ${VAR}, so whether it blocks this server depends on the env Claude starts with")
	}
	return true
}

// checkAllow applies the allowlist. The organization's own servers skip it.
func (p *mcpPolicy) checkAllow(d *def) {
	if !p.allowSet || d.rank == rankManagedSettings || (d.rank == rankManagedFile && !d.raw.vars) {
		return
	}
	switch p.allowed(d.raw) {
	case matchYes:
	case matchUnsettled:
		d.maybe("an allowedMcpServers entry uses ${VAR}, so whether it allows this server depends on the env Claude starts with")
	case matchNo:
		d.set(model.StartNo, "not allowed by allowedMcpServers")
	}
}

// allowed matches a server against the allowlist. A serverName entry only
// counts when the list has no serverUrl (for a remote server) or
// serverCommand (for stdio) entries.
func (p *mcpPolicy) allowed(s rawServer) matchResult {
	byURL := remote(transport(s.typ))
	strong := slices.ContainsFunc(p.allow, func(en policyEntry) bool {
		return (byURL && en.url != nil) || (!byURL && en.command != nil)
	})
	best := matchNo
	for _, en := range p.allow {
		if en.name != nil && strong {
			continue
		}
		switch matchEntry(en, s) {
		case matchYes:
			return matchYes
		case matchUnsettled:
			best = matchUnsettled
		case matchNo:
		}
	}
	return best
}

type matchResult int

const (
	matchNo matchResult = iota
	matchYes
	matchUnsettled // the literal values differ, but a ${VAR} could make them match
)

// matchEntry checks one list entry against a server. A serverCommand entry
// only matches stdio servers and a serverUrl entry only remote ones.
func matchEntry(en policyEntry, s rawServer) matchResult {
	switch {
	case en.name != nil:
		if *en.name == s.name {
			return matchYes
		}
		return matchNo
	case en.command != nil:
		return matchCommand(en.command, s)
	case en.url != nil:
		return matchURL(*en.url, s)
	}
	return matchNo
}

func matchCommand(want []string, s rawServer) matchResult {
	if transport(s.typ) != model.TransportStdio {
		return matchNo
	}
	cmd := append([]string{s.command}, s.args...)
	if slices.Equal(want, cmd) {
		return matchYes
	}
	if slices.ContainsFunc(want, hasVar) || slices.ContainsFunc(cmd, hasVar) {
		return matchUnsettled
	}
	return matchNo
}

func matchURL(pattern string, s rawServer) matchResult {
	if !remote(transport(s.typ)) {
		return matchNo
	}
	if urlMatches(pattern, s.url) {
		return matchYes
	}
	if hasVar(pattern) || hasVar(s.url) {
		return matchUnsettled
	}
	return matchNo
}

// providedProblem says why Claude drops a managedMcpServers entry, or "".
func providedProblem(s rawServer) string {
	t := transport(s.typ)
	switch {
	case t != model.TransportHTTP && t != model.TransportSSE:
		return "only http and sse servers can be provided"
	case !strings.HasPrefix(strings.ToLower(s.url), "https://"):
		return "the url isn't https://"
	case len(s.extra) > 0:
		return "it has a " + s.extra[0] + " member"
	case s.vars || hasVar(s.url):
		return "it uses a ${VAR} reference, which Claude doesn't expand here"
	case !providedName.MatchString(s.name):
		return "the name may only use letters, numbers, hyphens and underscores"
	}
	return ""
}

// providedName is the form Claude accepts for a provided server name.
var providedName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// rankScope names a rank for a why.
func rankScope(r int) string {
	return [...]string{"managed-mcp.json", "managedMcpServers", "local", "project", "user", "plugin"}[r]
}

// clashByName applies the same-name precedence between the managed, local,
// project and user scopes: the highest definition applies whole. When that
// one won't start itself, the docs don't say whether it still hides the
// lower ones, so they may start.
func clashByName(defs []def) {
	for i := range defs {
		d := &defs[i]
		if d.rank == rankPlugin {
			continue
		}
		for j := range defs {
			h := defs[j]
			if h.rank >= d.rank || h.rank == rankPlugin || h.raw.name != d.raw.name {
				continue
			}
			if h.start == model.StartYes {
				d.set(model.StartNo, "overridden by the "+rankScope(h.rank)+" server with the same name")
				break
			}
			d.maybe("a " + rankScope(h.rank) + " server with the same name is " + string(h.start) +
				"; the docs don't say whether it still hides this one")
		}
	}
}

// clashByEndpoint drops a plugin server that points at the same URL or
// command as a server above it that starts.
func clashByEndpoint(defs []def) {
	for i := range defs {
		d := &defs[i]
		if d.rank != rankPlugin || !d.starts() {
			continue
		}
		ep := endpoint(d.raw)
		for _, h := range defs {
			if h.rank == rankPlugin || endpoint(h.raw) != ep {
				continue
			}
			if h.start == model.StartYes {
				d.set(model.StartNo, "the same endpoint as the "+rankScope(h.rank)+" server "+h.raw.name+", so Claude connects that one")
				break
			}
			if h.start == model.StartMaybe {
				d.maybe("the " + rankScope(h.rank) + " server " + h.raw.name + " has the same endpoint and may start instead")
			}
		}
	}
}

// endpoint is what Claude compares plugin servers by: the URL, ignoring the
// case of the scheme and host, the scheme's default port and a trailing
// slash, or the command and its args.
func endpoint(s rawServer) string {
	if !remote(transport(s.typ)) {
		return "cmd\x00" + strings.Join(append([]string{s.command}, s.args...), "\x00")
	}
	u, err := url.Parse(s.url)
	if err != nil || u.Host == "" {
		return "url\x00" + s.url
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if port := u.Port(); port != "" && port != defaultPort(scheme) {
		host = net.JoinHostPort(host, port)
	}
	rest := strings.TrimSuffix(u.EscapedPath(), "/")
	if u.RawQuery != "" {
		rest += "?" + u.RawQuery
	}
	return "url\x00" + scheme + "://" + u.User.String() + "@" + host + rest
}

func defaultPort(scheme string) string {
	switch scheme {
	case "https", "wss":
		return "443"
	case typeHTTP, "ws":
		return "80"
	}
	return ""
}

// urlMatches checks a serverUrl pattern against a server URL. A * matches
// anything, including the whole scheme. The host is matched without case
// and without a trailing dot. A pattern with no path matches any path;
// paths keep their case.
func urlMatches(pattern, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	pScheme, rest, ok := strings.Cut(pattern, "://")
	if !ok {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	if pScheme != "*" && !strings.EqualFold(pScheme, scheme) {
		return false
	}
	hostPort, pPath, hasPath := strings.Cut(rest, "/")
	pHost, pPort := splitPatternHost(hostPort)
	pHost = strings.TrimSuffix(strings.ToLower(pHost), ".")
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if !glob(pHost, host) || !portMatches(pHost, pPort, scheme, u.Port()) {
		return false
	}
	if !hasPath {
		return true
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return glob("/"+pPath, path)
}

// portMatches checks the port. With none in the pattern, a host written out
// in full matches only the scheme's default port and a host with a * any.
func portMatches(pHost, pPort, scheme, port string) bool {
	if port == "" {
		port = defaultPort(scheme)
	}
	switch {
	case pPort == "*":
		return true
	case pPort != "":
		return pPort == port
	case strings.Contains(pHost, "*"):
		return true
	}
	return port == defaultPort(scheme)
}

// splitPatternHost splits host and port in a pattern, where either can be *.
func splitPatternHost(hp string) (string, string) {
	if strings.HasPrefix(hp, "[") {
		host, rest, ok := strings.Cut(hp[1:], "]")
		if !ok {
			return hp, ""
		}
		return host, strings.TrimPrefix(rest, ":")
	}
	if host, port, ok := strings.CutLast(hp, ":"); ok {
		return host, port
	}
	return hp, ""
}

// glob matches s against a pattern where * matches any run of characters.
func glob(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	re, err := regexp.Compile("^" + strings.Join(parts, ".*") + "$")
	return err == nil && re.MatchString(s)
}

// approves says whether a layer approves any .mcp.json server.
func approves(l *layer) bool {
	return (l.mcpEnableAll != nil && *l.mcpEnableAll) || len(l.mcpEnabled) > 0
}
