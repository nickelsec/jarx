package cli

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/agent/claude"
	"github.com/nickelsec/jarx/internal/agent/codex"
	"github.com/nickelsec/jarx/internal/discover"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/jarxdir"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
	"github.com/nickelsec/jarx/internal/report"
)

const scanUsage = `usage: jarx scan [--home <dir>] [path...]

Scans what Claude Code and Codex can see and reach on this machine.

Extra paths are scanned along with the projects the agents know about, for
this run only.

flags:
  --home <dir>  use <dir> as the home dir instead of the real one
  -h, --help    show this help
`

func scanHelp(s *report.Stream) { s.Printf(scanUsage) }

func runScan(p *report.Printer, plain *redact.Scrubber, args []string) int {
	fs := newFlagSet("scan")
	home := fs.String("home", "", "")
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

	printEnv(p.Out, scrub, env, files)
	res := discover.Run(
		agent.Context{Env: env, Files: files, Scrub: scrub},
		[]agent.Adapter{claude.Adapter{}, codex.Adapter{}, discover.Saved(configPath(env), cfg.Repos)},
		fs.Args(),
	)
	p.Out.Printf("\n")
	p.Projects(res.Projects)
	p.Unknown(res.Unknown)
	p.Instructions(res.Instructions)
	p.Findings(res.Findings, rules)
	return exitOK
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
	scrub, err := redact.New(nil, redact.KeyFromState(env))
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
	all := slices.Concat(finding.Rules(), claude.Rules(), codex.Rules())
	r, err := finding.NewRegistry(all...)
	if err != nil {
		return nil, fmt.Errorf("building the rule registry: %w", err)
	}
	return r, nil
}
