// Package mcpconfig holds jarx's rules on MCP server definitions: how each
// server is installed and started, and what its config hands it. They read
// the model only, so they work the same for every agent. Rules that need an
// agent's precedence (a repository server taking your server's name) live
// in the adapters instead.
//
// A server is checked when the agent would start it, may start it, or is
// waiting on an approval: one waiting to be approved is exactly the one a
// repository wants started. Overridden, blocked and rejected definitions
// aren't checked.
package mcpconfig

import (
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
)

// check is one rule's test: the evidence when it applies, or "".
type check struct {
	rule finding.Rule
	test func(c ctx, s server) string
}

// ctx is what checks know about the machine.
type ctx struct{ env platform.Env }

// server is a definition's fields as the checks read them, already masked.
type server struct {
	m       model.Server
	name    string
	command string
	args    []string
}

// Analyze runs every rule over the servers in projects. A definition that
// applies in several projects is reported once.
func Analyze(s *redact.Scrubber, env platform.Env, projects []model.Project) []finding.Finding {
	c := ctx{env: env}
	seen := map[string]bool{}
	var out []finding.Finding
	for _, p := range projects {
		for _, m := range p.Servers {
			if m.Start == model.StartNo {
				continue
			}
			sv := newServer(m)
			for _, ch := range checks() {
				ev := ch.test(c, sv)
				key := ch.rule.ID + "\x00" + string(m.Origin.Agent) + "\x00" + m.Origin.File.Raw() + "\x00" + sv.name
				if ev == "" || seen[key] {
					continue
				}
				seen[key] = true
				t, _ := s.Scrub(ev)
				out = append(out, ch.rule.New(m.Origin, t))
			}
		}
	}
	return out
}

func newServer(m model.Server) server {
	sv := server{m: m, name: m.Name.String(), command: m.Command.String()}
	for _, a := range m.Args {
		sv.args = append(sv.args, a.String())
	}
	return sv
}

func (s server) line() string { return strings.TrimSpace(s.command + " " + strings.Join(s.args, " ")) }

func (s server) stdio() bool { return s.m.Transport == model.TransportStdio }

func checks() []check {
	return []check{
		{UnpinnedRunner(), unpinnedRunner},
		{UnpinnedImage(), unpinnedImage},
		{ShellCommand(), shellCommand},
		{TempBinary(), tempBinary},
		{GitBranch(), gitBranch},
		{RepoScript(), repoScript},
		{ForwardsSecret(), forwardsSecret},
		{PlainHTTP(), plainHTTP},
		{HeadersHelper(), headersHelper},
		{BroadFilesystem(), broadFilesystem},
		{RepoBatchArgs(), func(c ctx, s server) string { return batchArgs(c, s, true) }},
		{OwnBatchArgs(), func(c ctx, s server) string { return batchArgs(c, s, false) }},
	}
}

// base is a command's program name: no dir, lowercase, no .exe, .cmd or
// .bat.
func base(cmd string) string {
	if i := strings.LastIndexAny(cmd, `/\`); i >= 0 {
		cmd = cmd[i+1:]
	}
	cmd = strings.ToLower(cmd)
	for _, ext := range []string{".exe", ".cmd", ".bat"} {
		cmd = strings.TrimSuffix(cmd, ext)
	}
	return cmd
}

// positional is the args that aren't flags, and the values of the flags
// named in valued.
func positional(args, valued []string) ([]string, map[string][]string) {
	var pos []string
	vals := map[string][]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, v, inline := strings.Cut(a, "=")
		switch {
		case slices.Contains(valued, name) && inline:
			vals[name] = append(vals[name], v)
		case slices.Contains(valued, a) && i+1 < len(args):
			vals[a] = append(vals[a], args[i+1])
			i++
		case !strings.HasPrefix(a, "-"):
			pos = append(pos, a)
		}
	}
	return pos, vals
}

// packages is what a package runner installs: the package specs, and
// whether it's a Python runner (whose pins are name==version).
func packages(s server) ([]string, bool) {
	if !s.stdio() {
		return nil, false
	}
	args, python, ok := runnerArgs(base(s.command), s.args)
	if !ok {
		return nil, false
	}
	if python {
		return firstSpec(args, []string{"--from", "--spec"}, []string{"--with", "--python", "-p"}), true
	}
	return firstSpec(args, []string{"-p", "--package"}, []string{"-c", "--call"}), false
}

// runnerArgs says whether a command is a package runner, and gives the args
// after its run word (npm exec, pnpm dlx, uv tool run) and whether it's a
// Python one.
func runnerArgs(b string, args []string) ([]string, bool, bool) {
	for _, r := range runners {
		if r.prog != b {
			continue
		}
		if r.words == nil {
			return args, r.python, true
		}
		for _, w := range r.words {
			if len(args) >= len(w) && slices.Equal(args[:len(w)], w) {
				return args[len(w):], r.python, true
			}
		}
	}
	return nil, false, false
}

// runWord is the subcommand several runners use.
const runWord = "run"

// runner is a package runner: its program, the words that make it run a
// package (none when the program itself does), and whether it's Python's.
type runner struct {
	prog   string
	words  [][]string
	python bool
}

//nolint:gochecknoglobals // fixed table, read only
var runners = []runner{
	{prog: "npx"}, {prog: "bunx"},
	{prog: "pnpm", words: [][]string{{"dlx"}, {"x"}}}, {prog: "yarn", words: [][]string{{"dlx"}}}, {prog: "bun", words: [][]string{{"x"}}},
	{prog: "npm", words: [][]string{{"exec"}, {"x"}}},
	{prog: "uvx", python: true}, {prog: "pipx", words: [][]string{{runWord}}, python: true},
	{prog: "uv", words: [][]string{{"tool", runWord}}, python: true},
}

// firstSpec is the package a runner installs: the values of the flags that
// name it, or else the first positional arg. other are flags that take a
// value but don't name the package.
func firstSpec(args, named, other []string) []string {
	pos, vals := positional(args, slices.Concat(named, other))
	var specs []string
	for _, n := range named {
		specs = append(specs, vals[n]...)
	}
	if len(specs) == 0 && len(pos) > 0 {
		specs = pos[:1]
	}
	return specs
}

var (
	exactSemver = regexp.MustCompile(`^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$`)
	commitRef   = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
	pyPin       = regexp.MustCompile(`==\s*\d[\w.!+-]*$`)
)

// gitSpec says whether a spec installs from git, and whether it's pinned to
// a commit.
func gitSpec(spec string) (bool, bool) {
	if !gitSource(strings.ToLower(spec)) {
		return false, false
	}
	return true, commitRef.MatchString(gitRef(spec))
}

// gitSource says whether a lowercase spec is a git repository.
func gitSource(lower string) bool {
	for _, p := range []string{"git+", "git://", "github:", "gitlab:", "bitbucket:"} {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return strings.HasPrefix(lower, "https://") && (strings.Contains(lower, "github.com/") || strings.HasSuffix(lower, ".git"))
}

// gitRef is the ref a git spec names: after a #, or after an @ that comes
// after the host (git+https://host/repo@ref), or "".
func gitRef(spec string) string {
	if _, ref, ok := strings.Cut(spec, "#"); ok {
		return ref
	}
	_, rest, hasScheme := strings.Cut(spec, "://")
	if !hasScheme {
		rest = spec
	}
	if _, ref, ok := strings.CutLast(rest, "@"); ok && !strings.Contains(ref, "/") {
		return ref
	}
	return ""
}

// npmPinned says whether an npm spec names an exact version.
func npmPinned(spec string) bool {
	i := strings.LastIndex(spec, "@")
	if i <= 0 { // no version, or only a scope's leading @
		return false
	}
	return exactSemver.MatchString(spec[i+1:])
}

func unpinnedRunner(_ ctx, s server) string {
	specs, python := packages(s)
	for _, spec := range specs {
		if isGit, _ := gitSpec(spec); isGit || strings.Contains(spec, "REDACTED") {
			continue // git refs are GitBranch's
		}
		pinned := npmPinned(spec)
		if python {
			pinned = pyPin.MatchString(spec) || npmPinned(spec)
		}
		if !pinned {
			return s.name + " runs " + s.line() + ", and " + spec + " has no exact version"
		}
	}
	return ""
}

func gitBranch(_ ctx, s server) string {
	specs, _ := packages(s)
	for _, spec := range specs {
		if isGit, pinned := gitSpec(spec); isGit && !pinned {
			return s.name + " installs " + spec + ", which isn't pinned to a commit"
		}
	}
	return ""
}

// dockerValued are the docker run flags that take a value, so the image is
// the first positional arg after them.
//
//nolint:gochecknoglobals // fixed list, read only
var dockerValued = []string{
	"-e", "--env", "--env-file", "-v", "--volume", "--mount", "--name", "-p", "--publish", "--network", "--net",
	"--entrypoint", "-w", "--workdir", "-u", "--user", "-l", "--label", "--platform", "--pull", "--cpus", "-m", "--memory",
	"--add-host", "--cap-add", "--cap-drop", "--device", "--security-opt", "--hostname", "-h", "--ulimit", "--tmpfs",
}

func unpinnedImage(_ ctx, s server) string {
	b := base(s.command)
	if !s.stdio() || (b != "docker" && b != "podman" && b != "nerdctl") {
		return ""
	}
	run := slices.Index(s.args, runWord)
	if run < 0 {
		return ""
	}
	pos, _ := positional(s.args[run+1:], dockerValued)
	if len(pos) == 0 {
		return ""
	}
	// A digest (image@sha256:...) counts as a tag here: it has a ':' after
	// the last '/'.
	image := pos[0]
	tag := ""
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		tag = image[i+1:]
	}
	if tag == "" || tag == "latest" {
		return s.name + " runs the image " + image + " with no pinned tag"
	}
	return ""
}

// shellFlag says whether an arg tells a shell to run a string.
func shellFlag(b, a string) bool {
	lower := strings.ToLower(a)
	switch b {
	case "sh", "bash", "zsh", "dash", "ksh", "fish", "ash":
		return regexp.MustCompile(`^-[a-z]*c[a-z]*$`).MatchString(a)
	case "cmd":
		return lower == "/c" || lower == "/k"
	case "powershell", "pwsh":
		return slices.Contains([]string{"-c", "-command", "-encodedcommand", "-e", "-ec", "-enc"}, lower)
	}
	return false
}

func shellCommand(_ ctx, s server) string {
	if !s.stdio() {
		return ""
	}
	b := base(s.command)
	if slices.ContainsFunc(s.args, func(a string) bool { return shellFlag(b, a) }) {
		return s.name + " runs " + s.line()
	}
	return ""
}

// tempDirs are dirs anything can write to, as path parts.
//
//nolint:gochecknoglobals // fixed list, read only
var tempDirs = []string{"/tmp/", "/var/tmp/", "/private/tmp/", "/dev/shm/", "/appdata/local/temp/", "/windows/temp/"}

func slashes(p string) string { return strings.ToLower(strings.ReplaceAll(p, `\`, "/")) }

func tempBinary(c ctx, s server) string {
	if !s.stdio() || s.command == "" {
		return ""
	}
	p := slashes(s.command)
	for _, d := range writableDirs(c.env) {
		// The Windows ones sit under a drive and a user, so they match
		// anywhere in the path; the rest match from the start.
		if strings.HasPrefix(p, d) || (strings.HasPrefix(d, "/appdata/") || strings.HasPrefix(d, "/windows/")) && strings.Contains(p, d) {
			return s.name + " runs " + s.command + ", which is in a temp or downloads dir"
		}
	}
	return ""
}

// writableDirs are the temp dirs, the env's own temp dirs and the
// downloads dir, as lowercase slash paths ending in a slash.
func writableDirs(env platform.Env) []string {
	dirs := slices.Clone(tempDirs)
	if env.Home != "" {
		dirs = append(dirs, strings.TrimSuffix(slashes(env.Home), "/")+"/downloads/")
	}
	for _, v := range []string{"TEMP", "TMP", "TMPDIR"} {
		if d, ok := env.Lookup(v); ok && d != "" {
			dirs = append(dirs, strings.TrimSuffix(slashes(d), "/")+"/")
		}
	}
	return dirs
}

// interpreters run a script file named in their args.
//
//nolint:gochecknoglobals // fixed list, read only
var interpreters = []string{"node", "python", "python3", "deno", "bun", "ruby", "php", "perl", "tsx", "ts-node", "bash", "sh", "pwsh", "powershell"}

// relative says whether a path is a file in the project: not absolute, not
// a flag, and with a dir in it or a script's extension.
func relative(p string) bool {
	if p == "" || strings.HasPrefix(p, "-") || strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) ||
		regexp.MustCompile(`^[A-Za-z]:`).MatchString(p) || strings.HasPrefix(p, "~") || strings.HasPrefix(p, "$") {
		return false
	}
	if strings.ContainsAny(p, `/\`) {
		return true
	}
	ext := strings.ToLower(p[strings.LastIndex(p, ".")+1:])
	return strings.Contains(p, ".") && slices.Contains([]string{"js", "mjs", "cjs", "ts", "py", "rb", "php", "pl", "sh", "ps1"}, ext)
}

func repoScript(_ ctx, s server) string {
	if !s.stdio() || s.m.Origin.Scope != model.ScopeProject {
		return ""
	}
	if relative(s.command) {
		return s.name + " runs " + s.command + " from the repository"
	}
	if !slices.Contains(interpreters, base(s.command)) {
		return ""
	}
	pos, _ := positional(s.args, nil)
	if len(pos) > 1 && pos[0] == runWord {
		pos = pos[1:] // deno run, bun run
	}
	if len(pos) > 0 && relative(pos[0]) {
		return s.name + " runs " + s.line() + ", a script in the repository"
	}
	return ""
}

var secretName = regexp.MustCompile(`(?i)(token|secret|passw(or)?d|api_?key|private_?key|credential|(^|_)auth($|_)|(^|_)key$)`)

func forwardsSecret(_ ctx, s server) string {
	var names []string
	for _, v := range s.m.ForwardEnv {
		if n := strings.TrimSuffix(v.String(), " (remote)"); secretName.MatchString(n) {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return ""
	}
	return s.name + " forwards " + strings.Join(names, ", ") + " from your env"
}

// loopback says whether a URL's host is this machine.
func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func plainHTTP(_ ctx, s server) string {
	if s.stdio() {
		return ""
	}
	u, err := url.Parse(s.m.URL.String())
	if err != nil || !strings.EqualFold(u.Scheme, "http") || loopback(u.Hostname()) {
		return ""
	}
	return s.name + " connects to " + u.Scheme + "://" + u.Host + " without TLS"
}

func headersHelper(_ ctx, s server) string {
	if s.m.HeadersHelper.IsZero() {
		return ""
	}
	return s.name + " runs " + s.m.HeadersHelper.String() + " to get its headers"
}

func broadFilesystem(c ctx, s server) string {
	if !s.stdio() {
		return ""
	}
	home := strings.TrimRight(slashes(c.env.Home), "/")
	for _, a := range s.args {
		p := slashes(a)
		trimmed := strings.TrimRight(p, "/")
		switch {
		case p == "/", trimmed == "~", trimmed == "$home", trimmed == "${home}", trimmed == "%userprofile%", trimmed == "${userprofile}",
			home != "" && trimmed == home, regexp.MustCompile(`^[a-z]:/?$`).MatchString(p):
			return s.name + " is given " + a
		}
	}
	return ""
}

// batchChars are what cmd.exe reads as syntax; see internal/proc.
const batchChars = "&|<>^%!\"()\r\n"

// windowsShims are package runners that are .cmd files on Windows.
//
//nolint:gochecknoglobals // fixed list, read only
var windowsShims = []string{"npx", "npm", "pnpm", "yarn", "corepack"}

func batchArgs(c ctx, s server, repo bool) string {
	if !s.stdio() {
		return ""
	}
	fromRepo := s.m.Origin.Scope == model.ScopeProject || s.m.Origin.Scope == model.ScopePlugin
	if fromRepo != repo {
		return ""
	}
	if !isBatch(c.env.GOOS, s.command) || !slices.ContainsFunc(s.args, func(a string) bool { return strings.ContainsAny(a, batchChars) }) {
		return ""
	}
	return s.name + " runs " + s.line() + " through cmd.exe"
}

// isBatch says whether a command runs through cmd.exe: a .bat or .cmd
// file, or on Windows a bare package runner that's one.
func isBatch(goos, command string) bool {
	lower := strings.ToLower(command)
	if strings.HasSuffix(lower, ".cmd") || strings.HasSuffix(lower, ".bat") {
		return true
	}
	return goos == "windows" && !strings.Contains(lower, ".") && slices.Contains(windowsShims, base(command))
}
