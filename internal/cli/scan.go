package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"

	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/platform"
)

const scanUsage = `usage: jarx scan [--home <dir>]

Scans what Claude Code and Codex can see and reach on this machine.

flags:
  --home <dir>  use <dir> as the home dir instead of the real one
  -h, --help    show this help
`

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("scan")
	home := fs.String("home", "", "")
	if code, ok := parse(fs, args, scanUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() > 0 {
		return usageError(stderr, fmt.Sprintf("unexpected argument %q", fs.Arg(0)), scanUsage)
	}
	homeSet := false
	fs.Visit(func(f *flag.Flag) { homeSet = homeSet || f.Name == "home" })
	if homeSet && *home == "" {
		return usageError(stderr, "--home needs a directory", scanUsage)
	}

	var env platform.Env
	var err error
	if *home != "" {
		env, err = platform.FromHome(*home)
	} else {
		env, err = platform.Real()
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "jarx: %v\n", err)
		return exitError
	}
	files, err := fsys.New(env)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "jarx: %v\n", err)
		return exitError
	}
	defer func() { _ = files.Close() }()

	printEnv(stdout, env, files)
	return exitOK
}

// printEnv shows what platform resolved and whether each path exists. It
// prints the env var count only, never names or values. It reads nothing but
// file info and writes nothing.
func printEnv(w io.Writer, env platform.Env, files *fsys.FS) {
	source := "this machine"
	envLine := plural(env.VarCount(), "var", "vars") + " from the process"
	if env.Fake() {
		source = "fake home"
		envLine = plural(env.VarCount(), "var", "vars") + " from " + platform.JarxEnvName
		if _, err := files.Stat(filepath.Join(env.Home, platform.JarxEnvName)); err != nil {
			envLine = "no " + platform.JarxEnvName + ", empty env"
		}
	}
	stateStatus := pathStatus(files, env.StateDir)
	if stateStatus == statusMissing {
		stateStatus = "not created yet"
	}

	_, _ = fmt.Fprintf(w, "environment (%s)\n", source)
	row := func(label, value string) { _, _ = fmt.Fprintf(w, "  %-12s %s\n", label, value) }
	withStatus := func(path, status string) string { return path + "  (" + status + ")" }
	row("home", withStatus(env.Home, pathStatus(files, env.Home)))
	row("os", env.GOOS)
	row("env", envLine)
	row("PATH", plural(len(env.Path), "entry", "entries"))
	row("state dir", withStatus(env.StateDir, stateStatus))

	roots, ok := env.SystemRoots()
	if !ok {
		row("system dirs", "skipped (--home)")
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
		row(label, "none found")
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
	return fmt.Sprintf("%d %s", n, many)
}
