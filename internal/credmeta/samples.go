package credmeta

import (
	"path/filepath"
	"sort"

	"github.com/nickelsec/jarx/internal/platform"
)

// Sample is one example credential path. Rules that grant access to paths
// test their patterns against these, so they use the same list Location
// checks against.
type Sample struct {
	Path string
	Kind string
}

// Samples is one path for every kind of credential location: the agents'
// login files, the fixed files under the home dir, a file in each
// credential dir, and, for a project dir, its .env and a private key.
func Samples(env platform.Env, project string) []Sample {
	out := []Sample{
		{filepath.Join(configDir(env, "CLAUDE_CONFIG_DIR", ".claude"), ".credentials.json"), "claude_login"},
		{filepath.Join(configDir(env, "CODEX_HOME", ".codex"), "auth.json"), "codex_login"},
	}
	for _, rel := range sortedKeys(homeFiles) {
		out = append(out, Sample{filepath.Join(env.Home, filepath.FromSlash(rel)), homeFiles[rel]})
	}
	for _, rel := range sortedKeys(homeDirs) {
		name := "credentials"
		if homeDirs[rel] == "ssh" {
			name = keyNames[len(keyNames)-1] // id_ed25519, the usual key name
		}
		out = append(out, Sample{filepath.Join(env.Home, filepath.FromSlash(rel), name), homeDirs[rel]})
	}
	if project != "" {
		out = append(out,
			Sample{filepath.Join(project, ".env"), "env_file"},
			Sample{filepath.Join(project, "deploy"+keyExts[0]), "private_key"},
		)
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
