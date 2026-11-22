// Package codex is the Codex CLI adapter.
//
// Project records come from projects.<path>.trust_level in the user
// config.toml under CODEX_HOME (default ~/.codex). Documented at
// developers.openai.com/codex/config-reference: "trusted" | "untrusted".
package codex

import (
	"errors"
	"io/fs"
	"path/filepath"

	"github.com/BurntSushi/toml"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
)

// Adapter is the Codex CLI adapter.
type Adapter struct{}

// Agent returns codex.
func (Adapter) Agent() model.Agent { return model.AgentCodex }

func configFile(env platform.Env) string {
	if dir, ok := env.Lookup("CODEX_HOME"); ok && dir != "" {
		return filepath.Join(env.MapPath(dir), "config.toml")
	}
	return filepath.Join(env.Home, ".codex", "config.toml")
}

type config struct {
	Projects map[string]struct {
		TrustLevel *string `toml:"trust_level"`
	} `toml:"projects"`
}

// Projects returns the paths under [projects] in the user config.toml, with
// their trust_level.
func (Adapter) Projects(c agent.Context) ([]model.Project, []finding.Finding) {
	file := configFile(c.Env)
	origin := model.Origin{
		Agent:    model.AgentCodex,
		File:     model.NewPath(c.Scrub, file),
		Scope:    model.ScopeUser,
		InEffect: true,
	}

	data, err := c.Files.ReadFile(file)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		// Too large is recorded by fsys and reported by discover; anything
		// else is an unreadable record.
		if errors.Is(err, fsys.ErrTooLarge) {
			return nil, nil
		}
		return nil, unreadable(c, origin, "couldn't read the file")
	}

	var cfg config
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		// The TOML error message quotes the line, so only its line number is
		// kept.
		if perr, ok := errors.AsType[toml.ParseError](err); ok {
			origin.Line = perr.Position.Line
		}
		return nil, unreadable(c, origin, "not valid TOML")
	}

	out := make([]model.Project, 0, len(cfg.Projects))
	for path, p := range cfg.Projects {
		proj := model.Project{
			Path:    model.NewPath(c.Scrub, c.Env.MapPath(path)),
			Origins: []model.Origin{origin},
		}
		if p.TrustLevel != nil {
			proj.Trust = []model.Trust{{Level: trustLevel(*p.TrustLevel), Origin: origin}}
		}
		out = append(out, proj)
	}
	return out, nil
}

func trustLevel(v string) model.TrustLevel {
	switch v {
	case "trusted":
		return model.TrustTrusted
	case "untrusted":
		return model.TrustUntrusted
	default:
		return model.TrustUnknown
	}
}

func unreadable(c agent.Context, origin model.Origin, why string) []finding.Finding {
	ev, _ := c.Scrub.Scrub(why)
	return []finding.Finding{finding.UnreadableRecord().New(origin, ev)}
}
