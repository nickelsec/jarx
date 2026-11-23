package model

import (
	"fmt"
	"io"
)

// Launch is what an agent would run or connect to for a server, raw: the
// real command, args, env values, URL and headers, tokens included. probe
// needs them to start the server the way the agent would. Like Path, it
// keeps the raw values unexported. Unlike Path it has no masked form at
// all: it prints as [launch] for every fmt verb and encodes as JSON null, so
// nothing in it reaches the terminal, a log, a snapshot or the dashboard.
// Only probe calls Spec: a forbidigo rule bans it everywhere else but tests.
type Launch struct {
	spec *LaunchSpec
}

// LaunchSpec is the raw launch data. ${VAR} references are as written; probe
// expands them the way the agent does.
type LaunchSpec struct {
	Command string
	Args    []string
	URL     string
	Env     [][2]string // name and value, as the config sets them
	Headers [][2]string
	// HeadersHelper says a command computes headers, which jarx won't run.
	HeadersHelper bool
	// OAuth says the server is set up for an OAuth sign-in jarx can't do:
	// Claude's oauth block, or Codex's auth set to oauth or chatgpt.
	OAuth bool
	// Codex: the working dir, the env vars it forwards (env_vars), the var
	// holding a bearer token, and headers filled from env vars.
	Cwd        string
	ForwardEnv []ForwardVar
	BearerVar  string
	HeaderVars [][2]string // header and var name
	// Where Claude's path variables point: ${CLAUDE_PROJECT_DIR},
	// ${CLAUDE_PLUGIN_ROOT} and ${CLAUDE_PLUGIN_DATA}.
	ProjectDir, PluginRoot, PluginData string
}

// ForwardVar is one Codex env_vars entry.
type ForwardVar struct {
	Name   string
	Remote bool // source = "remote": read on a remote executor, not here
}

// NewLaunch wraps a raw spec.
func NewLaunch(s LaunchSpec) Launch { return Launch{spec: &s} }

// Spec returns the raw spec. Only probe uses it, to start or reach the
// server.
func (l Launch) Spec() (LaunchSpec, bool) {
	if l.spec == nil {
		return LaunchSpec{}, false
	}
	return *l.spec, true
}

// Format prints [launch] for every verb, so the raw spec never shows.
func (l Launch) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "[launch]") }

// MarshalJSON encodes nothing of the spec.
func (l Launch) MarshalJSON() ([]byte, error) { return []byte("null"), nil }
