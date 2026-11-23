package fakemcp

import (
	"context"
	"encoding/json"
	"io"
)

// exitBadScript is Main's exit code for a script it can't use.
const exitBadScript = 2

// Main is the server side of the demo home's fake server: the jarx binary
// runs it in a hidden mode, and only when probe starts it under --home (see
// internal/probe). args is one JSON Script. It serves stdio until stdin
// closes and returns an exit code: exitBadScript for a script it can't use.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		_, _ = io.WriteString(stderr, "fakemcp: want one JSON script\n")
		return exitBadScript
	}
	var sc Script
	if err := json.Unmarshal([]byte(args[0]), &sc); err != nil { //nolint:musttag // a script's keys are its Go field names
		_, _ = io.WriteString(stderr, "fakemcp: the script isn't valid JSON\n")
		return exitBadScript
	}
	sc.Log = nil
	if err := New(sc).ServeStdio(context.Background(), stdin, stdout, stderr); err != nil {
		return 1
	}
	return 0
}
