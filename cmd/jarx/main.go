// Command jarx maps what Claude Code and Codex can see and reach on a machine.
package main

import (
	"os"

	"github.com/nickelsec/jarx/internal/cli"
	"github.com/nickelsec/jarx/internal/probe"
)

// version is set at build time with -ldflags "-X main.version=...".
var version string

func main() {
	// The demo home's fake MCP server is jarx itself in a hidden mode; see
	// internal/probe. It needs the raw streams, since they are the server's.
	if len(os.Args) > 1 && os.Args[1] == probe.DemoMode {
		os.Exit(cli.ServeDemo(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, version))
}
