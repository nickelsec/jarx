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

// Describer is an adapter for an agent installed on the machine, which the
// scan names with the dir its config lives in.
type Describer interface {
	Name() string
	ConfigDir(env platform.Env) string
}

// SettingsReader is an adapter that reads settings. Settings stores each
// project's result on it (only projects with status ok are read) and returns
// the keys it didn't recognize, once per file.
type SettingsReader interface {
	Settings(c Context, projects []model.Project) ([]model.Unknown, []finding.Finding)
}

// InstructionReader is an adapter that reads instruction texts. It stores
// each ok project's on the project and returns the ones it can't tie to a
// project.
type InstructionReader interface {
	Instructions(c Context, projects []model.Project) ([]model.Instruction, []finding.Finding)
}

// ExtensionReader is an adapter that reads what extends the agent: hooks,
// skills, commands, subagents and plugins. It stores each ok project's on
// the project. It only reads them; nothing they declare is ever run.
type ExtensionReader interface {
	Extensions(c Context, projects []model.Project) []finding.Finding
}
