// Package cli parses jarx's command line and runs the commands.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime/debug"
)

const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

const usage = `usage: jarx [--version] <command>

commands:
  scan   map what the agents can see and reach

flags:
  --version   print the jarx version
  -h, --help  show this help
`

// Run runs jarx with args (without the program name) and returns the exit
// code. ldflagsVersion is the version set at build time, or "".
func Run(args []string, stdout, stderr io.Writer, ldflagsVersion string) int {
	fs := newFlagSet("jarx")
	showVersion := fs.Bool("version", false, "")

	if code, ok := parse(fs, args, usage, stdout, stderr); !ok {
		return code
	}
	if *showVersion {
		info, _ := debug.ReadBuildInfo() // nil when not available
		_, _ = fmt.Fprintf(stdout, "jarx %s\n", versionFrom(ldflagsVersion, info))
		return exitOK
	}

	rest := fs.Args()
	if len(rest) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch rest[0] {
	case "scan":
		return runScan(rest[1:], stdout, stderr)
	default:
		return usageError(stderr, fmt.Sprintf("unknown command %q", rest[0]), usage)
	}
}

// newFlagSet returns a flag set that reports nothing itself, so parse decides
// where help and errors go.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return fs
}

// parse parses args into fs. Help goes to stdout with exit 0, and a bad flag
// goes to stderr with exit 2. It returns the exit code and whether the caller
// should keep going; when that's false, the caller returns the code.
func parse(fs *flag.FlagSet, args []string, help string, stdout, stderr io.Writer) (int, bool) {
	err := fs.Parse(args)
	switch {
	case err == nil:
		return exitOK, true
	case errors.Is(err, flag.ErrHelp):
		_, _ = fmt.Fprint(stdout, help)
		return exitOK, false
	default:
		return usageError(stderr, err.Error(), help), false
	}
}

func usageError(stderr io.Writer, msg, help string) int {
	_, _ = fmt.Fprintf(stderr, "jarx: %s\n\n%s", msg, help)
	return exitUsage
}

// versionFrom picks the ldflags version, then the module version that
// go install records, then "dev".
func versionFrom(ldflags string, info *debug.BuildInfo) string {
	if ldflags != "" {
		return ldflags
	}
	if info != nil && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}
