// Package agent holds the adapter interface. An adapter knows one agent's
// paths, formats and quirks, and turns them into the shared model. Nothing
// outside an adapter knows an agent's file layout.
package agent

import (
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
)

// Context is what every adapter reads through.
type Context struct {
	Env   platform.Env
	Files *fsys.FS
	Scrub *redact.Scrubber
}

// Adapter reads one agent's records.
type Adapter interface {
	Agent() model.Agent
	// Projects returns the projects the agent's own records name. Status is
	// left for discover to fill in.
	Projects(c Context) ([]model.Project, []finding.Finding)
}
