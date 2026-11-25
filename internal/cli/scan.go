package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/agent/claude"
	"github.com/nickelsec/jarx/internal/agent/codex"
	"github.com/nickelsec/jarx/internal/analyze/capability"
	"github.com/nickelsec/jarx/internal/analyze/drift"
	"github.com/nickelsec/jarx/internal/analyze/egress"
	"github.com/nickelsec/jarx/internal/analyze/mcpconfig"
	"github.com/nickelsec/jarx/internal/analyze/perms"
	"github.com/nickelsec/jarx/internal/analyze/poison"
	"github.com/nickelsec/jarx/internal/analyze/reach"
	"github.com/nickelsec/jarx/internal/analyze/secrets"
	"github.com/nickelsec/jarx/internal/analyze/unknown"
	"github.com/nickelsec/jarx/internal/analyze/versions"
	"github.com/nickelsec/jarx/internal/catalog"
	"github.com/nickelsec/jarx/internal/discover"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/history"
	"github.com/nickelsec/jarx/internal/jarxdir"
	"github.com/nickelsec/jarx/internal/llm"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/netguard"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/probe"
	"github.com/nickelsec/jarx/internal/redact"
	"github.com/nickelsec/jarx/internal/report"
	"github.com/nickelsec/jarx/internal/snapshot"
)

const scanUsage = `usage: jarx scan [--home <dir>] [--all] [--no-probe] [--no-history] [--llm] [path...]

Scans what Claude Code and Codex can see and reach on this machine.

Extra paths are scanned along with the projects the agents know about, for
this run only.

flags:
  --home <dir>  use <dir> as the home dir instead of the real one
  --all         show every finding in full, and the whole inventory
  --no-probe    don't start or contact any MCP server
  --no-history  don't read session history
  --llm         after showing what it would send and asking, send the
                masked artifacts to the LLM set up with jarx setup llm
  -h, --help    show this help
`

func scanHelp(s *report.Stream) { s.Printf(scanUsage) }

// The scan's steps, as the progress line names them.
const (
	stepHistory  = "reading session history"
	stepConfig   = "reading agent config"
	stepWalk     = "walking projects"
	stepProbe    = "probing MCP servers"
	stepFindings = "checking findings"
)

// scanSteps is a scan's steps in order: the progress line lines them up,
// and the dashboard lists them while a rescan runs.
//
//nolint:gochecknoglobals // fixed list, read only
var scanSteps = []string{stepHistory, stepConfig, stepWalk, stepProbe, stepFindings}

// scanFlags are jarx scan's flags.
type scanFlags struct {
	home                         string
	all, noProbe, noHistory, llm bool
	paths                        []string
}

// parseScan checks the flags. When ok is false, the caller returns code.
// --llm without a terminal is refused here, before anything is scanned.
func parseScan(p *report.Printer, plain *redact.Scrubber, args []string, st streams) (scanFlags, int, bool) {
	var f scanFlags
	fs := newFlagSet("scan")
	fs.StringVar(&f.home, "home", "", "")
	fs.BoolVar(&f.all, "all", false, "")
	fs.BoolVar(&f.noProbe, "no-probe", false, "")
	fs.BoolVar(&f.noHistory, "no-history", false, "")
	fs.BoolVar(&f.llm, "llm", false, "")
	if code, ok := parse(p, plain, fs, args, scanHelp); !ok {
		return f, code, false
	}
	if emptyHome(fs, f.home) {
		return f, usageError(p, scanHelp, scrubbed(plain, "--home needs a directory")), false
	}
	if f.llm && !st.interactive {
		p.Err.Printf("jarx: jarx scan --llm asks before sending anything, so it needs a terminal. run it in one, or drop --llm\n")
		return f, exitUsage, false
	}
	f.paths = fs.Args()
	return f, exitOK, true
}

// scanSetup is what a scan needs before it reads anything about the agents.
type scanSetup struct {
	env    platform.Env
	files  *fsys.FS
	scrub  *redact.Scrubber
	cfg    jarxdir.Config
	rules  *finding.Registry
	review *llmRun // nil without --llm
}

// openScan builds the env, loads jarx's config and the rules, and with
// --llm checks the review can run. The caller closes files.
func openScan(p *report.Printer, f scanFlags, st streams) (scanSetup, bool) {
	env, files, scrub, err := openEnv(f.home)
	if err != nil {
		p.Error(err)
		return scanSetup{}, false
	}
	ss := scanSetup{env: env, files: files, scrub: scrub}
	if ss.cfg, err = jarxdir.LoadConfig(env); err == nil {
		ss.rules, err = scanRules()
	}
	if err != nil {
		_ = files.Close()
		p.Error(err)
		return scanSetup{}, false
	}
	if f.llm {
		if ss.review, err = prepareLLM(p, scrub, ss.cfg, st); err != nil {
			_ = files.Close()
			return scanSetup{}, false
		}
	}
	return ss, true
}

func runScan(p *report.Printer, plain *redact.Scrubber, args []string, st streams) int {
	f, code, ok := parseScan(p, plain, args, st)
	if !ok {
		return code
	}
	ss, ok := openScan(p, f, st)
	if !ok {
		return exitError
	}
	defer func() { _ = ss.files.Close() }()
	sc, err := scanOnce(p, ss, f)
	if err != nil {
		p.Error(err)
		return exitError
	}
	if f.all {
		// What platform resolved, in full, and before the scan saves its
		// snapshot, so the state dir shows as it was.
		p.Wrapped(model.Path{}, func() { printEnv(p.Out, ss.scrub, ss.env, ss.files) })
		p.Out.Printf("\n")
	}
	p.ScanHead(sc.view)
	code = exitOK
	if ss.review != nil {
		more, c, stop := ss.review.run(ss.env, sc.res.Projects)
		if stop {
			return c
		}
		code = c
		sc.view.Findings = append(slices.Clone(sc.findings), more...)
	}
	saveScan(ss, &sc)
	p.ScanBody(sc.view)
	return code
}

// scanned is one scan, before anything about it is printed or saved.
type scanned struct {
	view     report.ScanView
	findings []finding.Finding // the rules' own, without the LLM's
	res      discover.Result
	cursor   history.Cursor
}

// scanOnce reads, probes and analyzes, with the progress line on stderr.
// It prints nothing else and saves nothing.
func scanOnce(p *report.Printer, ss scanSetup, f scanFlags) (scanned, error) {
	env, files, scrub := ss.env, ss.files, ss.scrub
	g := p.StartProgress(scanSteps...)
	defer g.Stop()

	adapters := []agent.Adapter{claude.Adapter{}, codex.Adapter{}}
	c := agent.Context{Env: env, Files: files, Scrub: scrub}
	res, cursor, hist := discoverAll(c, append(slices.Clone(adapters), discover.Saved(configPath(env), ss.cfg.Repos)), f.paths, f.noHistory, g)
	self, _ := os.Executable() // runs the demo server under --home; probe never uses it elsewhere
	probe.Run(context.Background(), c, res.Projects, probe.Options{
		Disabled: f.noProbe, Client: netguard.New(), Self: self,
		OnProgress: func(done, running, total int) {
			if done == 0 && running == 0 && total > 0 {
				g.Count(stepProbe, total)
			}
			g.Set(done, running)
		},
	})
	g.Step(stepFindings)
	findings, err := analyze(scrub, env, res, lastSnapshot(env, files, scrub))
	g.Stop() // before anything else prints
	if err != nil {
		return scanned{}, err
	}
	view := report.ScanView{
		Fake: env.Fake(), Home: model.NewPath(scrub, env.Home), GOOS: env.GOOS,
		Agents:   agentInfo(env, files, scrub, adapters, res.Installs),
		Projects: res.Projects, Instructions: res.Instructions, Unknown: res.Unknown,
		Findings: findings, Rules: ss.rules, All: f.all, Credentials: res.Credentials,
		Sessions: hist.Sessions, HistoryFiles: hist.Files,
	}
	return scanned{view: view, findings: findings, res: res, cursor: cursor}, nil
}

// saveScan saves the snapshot and the history cursor, and puts what
// changed since the last snapshot on the view. The snapshot keeps the
// rules' findings only. The LLM's depend on the model and on whether --llm
// was passed, so they'd show as changes on every scan that differs.
func saveScan(ss scanSetup, sc *scanned) {
	sc.view.Since, sc.view.Note, sc.view.Changes, sc.view.SaveErr = saveSnapshot(ss.env, ss.scrub, snapshot.Input{
		Projects: sc.res.Projects, Instructions: sc.res.Instructions, Unknown: sc.res.Unknown, Findings: sc.findings,
		Credentials: sc.res.Credentials,
	})
	// Saved after --all printed the state dir as it was. A cursor that
	// can't be saved only means the next scan reads more.
	_ = sc.cursor.Save(ss.env)
}

// readHistory reads session history from where the last scan left off.
// The cursor is saved later, once --all has shown the state dir as it was.
// With --no-history nothing is read, and the empty cursor saves nothing.
func readHistory(c agent.Context, off bool) (history.Cursor, history.Result) {
	if off {
		return history.Cursor{}, history.Result{}
	}
	cursor := history.Load(c.Env)
	hist := history.Claude(c, &cursor, claude.Adapter{}.ConfigDir(c.Env))
	cx := history.Codex(c, &cursor, codex.Adapter{}.ConfigDir(c.Env), codex.Adapter{}.SQLiteHome(c))
	hist.Sessions = append(hist.Sessions, cx.Sessions...)
	hist.Findings = append(hist.Findings, cx.Findings...)
	hist.Files += cx.Files
	hist.Read += cx.Read
	return cursor, hist
}

// discoverAll reads history, then finds the projects: the sources' own and
// the dirs the agents ran in. Each project gets its sessions.
func discoverAll(c agent.Context, sources []agent.Adapter, extra []string, noHistory bool, g *report.Progress) (discover.Result, history.Cursor, history.Result) {
	if !noHistory {
		g.Step(stepHistory)
	}
	cursor, hist := readHistory(c, noHistory)
	g.Step(stepConfig)
	res := discover.RunWith(c, append(sources, historySource(c.Env, hist.Sessions)), extra, func(done, total int) {
		switch done {
		case 0:
			g.Count(stepWalk, total)
		case total:
			g.Step(stepConfig) // the adapters read settings and instructions next
		default:
			g.Set(done, 0)
		}
	})
	res.Findings = append(res.Findings, hist.Findings...)
	discover.AttachSessions(c.Env.GOOS, res.Projects, hist.Sessions)
	return res, cursor, hist
}

// historySource adds the dirs the agents ran in as projects. A session in
// an agent's own dir is its internal work.
func historySource(env platform.Env, sessions []model.Session) agent.Adapter {
	return discover.History(map[model.Agent]string{
		model.AgentClaude: claude.Adapter{}.ConfigDir(env),
		model.AgentCodex:  codex.Adapter{}.ConfigDir(env),
	}, sessions)
}

// windowEnd is where the 30 days of observed modes end: now, or under
// --home the newest session there, since a fake home is a snapshot whose
// verdicts shouldn't change from week to week.
func windowEnd(env platform.Env, projects []model.Project) time.Time {
	if !env.Fake() {
		return time.Now()
	}
	var newest time.Time
	for _, p := range projects {
		for _, s := range p.Sessions {
			if t := s.LastTime(); t.After(newest) {
				newest = t
			}
		}
	}
	if newest.IsZero() {
		return time.Now()
	}
	return newest
}

// analyze settles what's in effect and runs every analyzer.
func analyze(scrub *redact.Scrubber, env platform.Env, res discover.Result, prev snapshot.Snapshot) ([]finding.Finding, error) {
	perms.Settle(scrub, res.Projects)
	capability.Settle(scrub, res.Projects) // reads the settled permissions
	reach.Settle(scrub, env, res.Projects, res.Credentials)
	reach.Observe(scrub, res.Projects, windowEnd(env, res.Projects))
	egress.Settle(scrub, env, res.Projects, res.Credentials)
	permFindings, err := perms.Analyze(scrub, env, res.Projects)
	if err != nil {
		return nil, err //nolint:wrapcheck // perms names what failed
	}
	return slices.Concat(
		res.Findings,
		secrets.Analyze(scrub, res.Projects, res.Instructions),
		poison.Analyze(scrub, res.Projects, res.Instructions),
		mcpconfig.Analyze(scrub, env, res.Projects),
		capability.Analyze(scrub, res.Projects),
		drift.Analyze(scrub, prev, res.Projects),
		reach.Analyze(scrub, env, res.Projects),
		egress.Analyze(scrub, res.Projects),
		versions.Analyze(scrub, res.Installs),
		permFindings,
		unknown.Analyze(scrub, res.Unknown),
	), nil
}

// agentInfo names each agent and whether its config dir is there.
func agentInfo(env platform.Env, files *fsys.FS, scrub *redact.Scrubber, adapters []agent.Adapter, installs []model.Install) []report.AgentInfo {
	var out []report.AgentInfo
	for _, a := range adapters {
		d, ok := a.(agent.Describer)
		if !ok {
			continue
		}
		dir := d.ConfigDir(env)
		info, err := files.Stat(dir)
		var mine []model.Install
		for _, in := range installs {
			if in.Agent == a.Agent() {
				mine = append(mine, in)
			}
		}
		out = append(out, report.AgentInfo{
			Agent: a.Agent(), Name: d.Name(), ConfigDir: model.NewPath(scrub, dir), Found: err == nil && info.IsDir(),
			Installs: mine,
		})
	}
	return out
}

// saveSnapshot compares this scan with the last snapshot and saves this
// one. It returns when the last one was taken (zero for none), a note when
// there's nothing to compare against for another reason than a first scan,
// what changed, and any error saving. A snapshot problem never fails the
// scan.
func saveSnapshot(env platform.Env, scrub *redact.Scrubber, in snapshot.Input) (time.Time, string, []snapshot.Change, error) {
	d, err := jarxdir.Open(env)
	if err != nil {
		return time.Time{}, "couldn't open jarx's state dir", nil, fmt.Errorf("state dir: %w", err)
	}
	defer func() { _ = d.Close() }()
	prev, note, err := snapshot.Latest(d, scrub)
	if err != nil {
		note = "couldn't list earlier snapshots"
	}
	cur := snapshot.Build(scrub, time.Now(), in)
	var changes []snapshot.Change
	if !prev.Taken.IsZero() {
		changes = snapshot.Diff(scrub, prev, cur)
	}
	if err := snapshot.Save(d, cur); err != nil {
		return prev.Taken, note, changes, fmt.Errorf("write: %w", err)
	}
	// The run log only feeds the dashboard's history, so a log that can't
	// be saved doesn't fail the scan.
	_ = snapshot.AppendRun(d, snapshot.RunOf(cur.Taken, len(in.Findings), changes, prev.Taken.IsZero()))
	return prev.Taken, note, changes, nil
}

// emptyHome reports --home given with no value.
func emptyHome(fs *flag.FlagSet, home string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) { set = set || f.Name == "home" })
	return set && home == ""
}

// openEnv builds the Env (the fake home with --home, the real machine
// without), the fsys view on it and the scrubber. The fingerprint key is only
// created if a secret is actually found.
func openEnv(home string) (platform.Env, *fsys.FS, *redact.Scrubber, error) {
	var env platform.Env
	var err error
	if home != "" {
		env, err = platform.FromHome(home)
	} else {
		env, err = platform.Real()
	}
	if err != nil {
		return platform.Env{}, nil, nil, err //nolint:wrapcheck // platform errors already say what failed
	}
	files, err := fsys.New(env)
	if err != nil {
		return platform.Env{}, nil, nil, err //nolint:wrapcheck // fsys errors already say what failed
	}
	patterns, err := catalog.Secrets()
	if err != nil {
		_ = files.Close()
		return platform.Env{}, nil, nil, err //nolint:wrapcheck // catalog errors already say what failed
	}
	scrub, err := redact.New(patterns, redact.KeyFromState(env))
	if err != nil {
		_ = files.Close()
		return platform.Env{}, nil, nil, err //nolint:wrapcheck // redact errors already say what failed
	}
	return env, files, scrub, nil
}

// configPath is where jarx's own config lives, for origins and messages.
func configPath(env platform.Env) string {
	return filepath.Join(env.StateDir, "config.json")
}

// printEnv shows what platform resolved and whether each path exists. It
// prints the env var count only, never names or values. It reads nothing but
// file info and writes nothing.
func printEnv(out *report.Stream, s *redact.Scrubber, env platform.Env, files *fsys.FS) {
	t := func(raw string) redact.Text { return scrubbed(s, raw) }
	row := func(label string, value redact.Text) { out.Printf("  %-12s %s\n", t(label), value) }
	withStatus := func(path, status string) redact.Text { return t(path + "  (" + status + ")") }

	envLine := plural(env.VarCount(), "var", "vars") + " from the process"
	if env.Fake() {
		out.Printf("environment (fake home)\n")
		envLine = plural(env.VarCount(), "var", "vars") + " from " + platform.JarxEnvName
		if _, err := files.Stat(filepath.Join(env.Home, platform.JarxEnvName)); err != nil {
			envLine = "no " + platform.JarxEnvName + ", empty env"
		}
	} else {
		out.Printf("environment (this machine)\n")
	}
	stateStatus := pathStatus(files, env.StateDir)
	if stateStatus == statusMissing {
		stateStatus = "not created yet"
	}

	row("home", withStatus(env.Home, pathStatus(files, env.Home)))
	row("os", t(env.GOOS))
	row("env", t(envLine))
	row("PATH", t(plural(len(env.Path), "entry", "entries")))
	row("state dir", withStatus(env.StateDir, stateStatus))

	roots, ok := env.SystemRoots()
	if !ok {
		row("system dirs", t("skipped (--home)"))
		return
	}
	label, found := "system dirs", false
	for _, dir := range []string{roots.Etc, roots.LibraryAppSupport, roots.ProgramData, roots.ProgramFiles} {
		if dir == "" {
			continue
		}
		row(label, withStatus(dir, pathStatus(files, dir)))
		label, found = "", true
	}
	if !found {
		row(label, t("none found"))
	}
}

const statusMissing = "missing"

// pathStatus says whether the dir at path exists. Other errors become "can't
// check" and the error itself isn't shown.
func pathStatus(files *fsys.FS, path string) string {
	info, err := files.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return statusMissing
	case err != nil:
		return "can't check"
	case !info.IsDir():
		return "not a directory"
	default:
		return "exists"
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// scanRules is every rule a scan can report: finding's own and each
// adapter's.
func scanRules() (*finding.Registry, error) {
	all := slices.Concat(finding.Rules(), claude.Rules(), codex.Rules(), secrets.Rules(), poison.Rules(), perms.Rules(), unknown.Rules(), mcpconfig.Rules(), capability.Rules(), drift.Rules(), reach.Rules(), egress.Rules(), versions.Rules(), history.Rules(), llm.Rules())
	r, err := finding.NewRegistry(all...)
	if err != nil {
		return nil, fmt.Errorf("building the rule registry: %w", err)
	}
	return r, nil
}

// lastSnapshot is the previous scan's snapshot, for drift. Any trouble
// reading it means nothing to compare, the same as a first scan; saving
// reports it. It never creates the state dir.
func lastSnapshot(env platform.Env, files *fsys.FS, scrub *redact.Scrubber) snapshot.Snapshot {
	if _, err := files.Stat(env.StateDir); err != nil {
		return snapshot.Snapshot{} // no state dir yet, and opening one would create it
	}
	d, err := jarxdir.Open(env)
	if err != nil {
		return snapshot.Snapshot{}
	}
	defer func() { _ = d.Close() }()
	prev, _, err := snapshot.Latest(d, scrub)
	if err != nil {
		return snapshot.Snapshot{}
	}
	return prev
}
