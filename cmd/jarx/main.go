// Command jarx maps what Claude Code and Codex can see and reach on a machine.
package main

import (
	"os"

	"github.com/nickelsec/jarx/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=...".
var version string

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr, version))
}
