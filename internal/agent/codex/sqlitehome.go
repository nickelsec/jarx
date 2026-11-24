package codex

import "github.com/nickelsec/jarx/internal/agent"

// SQLiteHome is where Codex keeps its SQLite state: the user config's
// sqlite_home (config-reference: "Directory where Codex stores the
// SQLite-backed state DB"), else CODEX_HOME. The docs give no default;
// CODEX_HOME is where the files are observed.
func (Adapter) SQLiteHome(c agent.Context) string {
	s := &settings{c: c}
	s.load()
	for _, l := range []*layer{s.managed, s.user, s.system} {
		if l == nil {
			continue
		}
		if dir, ok := l.raw["sqlite_home"].(string); ok && dir != "" {
			return c.Env.MapPath(dir)
		}
	}
	return codexHome(c.Env)
}
