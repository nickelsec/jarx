package cli

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"

	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
	"github.com/nickelsec/jarx/internal/report"
)

const scanUsage = `usage: jarx scan [--home <dir>]

Scans what Claude Code and Codex can see and reach on this machine.

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
	if fs.NArg() > 0 {
		return usageError(p, scanHelp, scrubbed(plain, fmt.Sprintf("unexpected argument %q", fs.Arg(0))))
	}
	homeSet := false
	fs.Visit(func(f *flag.Flag) { homeSet = homeSet || f.Name == "home" })
	if homeSet && *home == "" {
		return usageError(p, scanHelp, scrubbed(plain, "--home needs a directory"))
	}

	var env platform.Env
	var err error
	if *home != "" {
		env, err = platform.FromHome(*home)
	} else {
		env, err = platform.Real()
	}
	if err != nil {
		p.Error(err)
		return exitError
	}
	files, err := fsys.New(env)
	if err != nil {
		p.Error(err)
		return exitError
	}
	defer func() { _ = files.Close() }()

	// The fingerprint key is only created if a secret is actually found.
	scrub, err := redact.New(nil, redact.KeyFromState(env))
	if err != nil {
		p.Error(err)
		return exitError
	}
	printEnv(p.Out, scrub, env, files)
	return exitOK
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
