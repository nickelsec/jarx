package cli

import (
	"io"

	"github.com/nickelsec/jarx/internal/fakemcp"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/probe"
)

// ServeDemo is jarx's hidden demo mode: it serves a fakemcp script on its own
// stdio. probe starts it only under --home, for the demo home's fake server,
// and sets probe.DemoMarker in its env. Without the marker it refuses, so
// typing the hidden mode by hand does nothing.
func ServeDemo(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if v, _ := platform.LookupReal(probe.DemoMarker); v != "1" {
		_, _ = io.WriteString(stderr, "jarx: this mode only runs as the demo home's fake MCP server\n")
		return exitUsage
	}
	return fakemcp.Main(args, stdin, stdout, stderr)
}
