package codex

import (
	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/model"
)

// Command is Codex's command name.
func (Adapter) Command() string { return "codex" }

// Installs finds Codex's npm install (@openai/codex). The openai/codex
// README also names the standalone installers, Homebrew and release
// binaries, but no doc says where the installers put Codex, so jarx
// doesn't guess: those show up through PATH instead.
func (Adapter) Installs(c agent.Context) []model.Install {
	return agent.NPMInstalls(c, model.AgentCodex, "@openai/codex")
}
