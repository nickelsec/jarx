package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

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
	printEnv(stdout, env)
	return exitOK
}

// printEnv shows what platform resolved. It prints the env var count only,
// never names or values.
func printEnv(w io.Writer, env platform.Env) {
	source, envFrom := "this machine", "from the process"
	if env.Fake() {
		source, envFrom = "fake home", "from .jarx-env"
	}
	system := "skipped (--home)"
	if roots, ok := env.SystemRoots(); ok {
		system = joinNonEmpty(roots.Etc, roots.LibraryAppSupport, roots.ProgramData, roots.ProgramFiles)
	}

	_, _ = fmt.Fprintf(w, "environment (%s)\n", source)
	row := func(label, value string) { _, _ = fmt.Fprintf(w, "  %-12s %s\n", label, value) }
	row("home", env.Home)
	row("os", env.GOOS)
	row("env", fmt.Sprintf("%d vars %s", env.VarCount(), envFrom))
	row("PATH", fmt.Sprintf("%d entries", len(env.Path)))
	row("state dir", env.StateDir)
	row("system dirs", system)
}

func joinNonEmpty(values ...string) string {
	var out []string
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return "none found"
	}
	return strings.Join(out, ", ")
}
