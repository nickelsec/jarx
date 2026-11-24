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
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/netguard"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/probe"
	"github.com/nickelsec/jarx/internal/redact"
	"github.com/nickelsec/jarx/internal/report"
	"github.com/nickelsec/jarx/internal/snapshot"
)

const scanUsage = `usage: jarx scan [--home <dir>] [--all] [--no-probe] [path...]

Scans what Claude Code and Codex can see and reach on this machine.

Extra paths are scanned along with the projects the agents know about, for
this run only.

flags:
  --home <dir>  use <dir> as the home dir instead of the real one
  --all         show every finding in full, and the whole inventory
  --no-probe    don't start or contact any MCP server
  -h, --help    show this help
`

func scanHelp(s *report.Stream) { s.Printf(scanUsage) }

func runScan(p *report.Printer, plain *redact.Scrubber, args []string) int {
	fs := newFlagSet("scan")
	home := fs.String("home", "", "")
	all := fs.Bool("all", false, "")
	noProbe := fs.Bool("no-probe", false, "")
	if code, ok := parse(p, plain, fs, args, scanHelp); !ok {
		return code
	}
	if emptyHome(fs, *home) {
		return usageError(p, scanHelp, scrubbed(plain, "--home needs a directory"))
	}

	env, files, scrub, err := openEnv(*home)
	if err != nil {
		p.Error(err)
		return exitError
	}
	defer func() { _ = files.Close() }()
	cfg, err := jarxdir.LoadConfig(env)
	if err != nil {
		p.Error(err)
		return exitError
	}
	rules, err := scanRules()
	if err != nil {
		p.Error(err)
		return exitError
	}

	adapters := []agent.Adapter{claude.Adapter{}, codex.Adapter{}}
	c := agent.Context{Env: env, Files: files, Scrub: scrub}
	res := discover.Run(c, append(slices.Clone(adapters), discover.Saved(configPath(env), cfg.Repos)), fs.Args())
	cursor, hist := readHistory(c, &res)
	self, _ := os.Executable() // runs the demo server under --home; probe never uses it elsewhere
	probe.Run(context.Background(), c, res.Projects, probe.Options{
		Disabled: *noProbe, Client: netguard.New(), Self: self,
	})
	findings, err := analyze(scrub, env, res, lastSnapshot(env, files, scrub))
	if err != nil {
		p.Error(err)
		return exitError
	}
	if *all {
		// What platform resolved, in full, and before the scan saves its
		// snapshot, so the state dir shows as it was.
		p.Wrapped(model.Path{}, func() { printEnv(p.Out, scrub, env, files) })
		p.Out.Printf("\n")
	}
	view := report.ScanView{
		Fake: env.Fake(), Home: model.NewPath(scrub, env.Home), GOOS: env.GOOS,
		Agents:   agentInfo(env, files, scrub, adapters, res.Installs),
		Projects: res.Projects, Instructions: res.Instructions, Unknown: res.Unknown,
		Findings: findings, Rules: rules, All: *all, Credentials: res.Credentials,
		Sessions: hist.Sessions, HistoryFiles: hist.Files,
	}
	view.Since, view.Note, view.Changes, view.SaveErr = saveSnapshot(env, scrub, snapshot.Input{
		Projects: res.Projects, Instructions: res.Instructions, Unknown: res.Unknown, Findings: findings,
		Credentials: res.Credentials,
	})
	// Saved after --all printed the state dir as it was. A cursor that
	// can't be saved only means the next scan reads more.
	_ = cursor.Save(env)
	p.Scan(view)
	return exitOK
}

// readHistory reads session history from where the last scan left off,
// adding its findings to res. The cursor is saved later, once --all has
// shown the state dir as it was.
func readHistory(c agent.Context, res *discover.Result) (history.Cursor, history.Result) {
	cursor := history.Load(c.Env)
	hist := history.Claude(c, &cursor, claude.Adapter{}.ConfigDir(c.Env))
	res.Findings = append(res.Findings, hist.Findings...)
	return cursor, hist
}

// analyze settles what's in effect and runs every analyzer.
func analyze(scrub *redact.Scrubber, env platform.Env, res discover.Result, prev snapshot.Snapshot) ([]finding.Finding, error) {
	perms.Settle(scrub, res.Projects)
	capability.Settle(scrub, res.Projects) // reads the settled permissions
	reach.Settle(scrub, env, res.Projects, res.Credentials)
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
	all := slices.Concat(finding.Rules(), claude.Rules(), codex.Rules(), secrets.Rules(), poison.Rules(), perms.Rules(), unknown.Rules(), mcpconfig.Rules(), capability.Rules(), drift.Rules(), reach.Rules(), egress.Rules(), versions.Rules(), history.Rules())
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
