// Command jarx maps what Claude Code and Codex can see and reach on a machine.
package main

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
)

// version is set at build time with -ldflags "-X main.version=...".
var version string

const (
	exitOK    = 0
	exitUsage = 2
)

const usage = `usage: jarx <command>

commands:
  version   print the jarx version
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "version":
		_, _ = fmt.Fprintf(stdout, "jarx %s\n", resolveVersion())
		return exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "jarx: unknown command %q\n\n%s", args[0], usage)
		return exitUsage
	}
}

func resolveVersion() string {
	info, _ := debug.ReadBuildInfo() // nil when not available
	return versionFrom(version, info)
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
