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

// Samples is one path for every kind of credential location: every place
// env puts a credential (a file in each credential dir), the defaults under
// the home dir, and, for a project dir, its .env and a private key.
func Samples(env platform.Env, project string) []Sample {
	var out []Sample
	seen := map[string]bool{}
	add := func(path, kind string) {
		if !seen[path] {
			seen[path] = true
			out = append(out, Sample{path, kind})
		}
	}
	for _, p := range Places(env) {
		if p.Dir {
			add(filepath.Join(p.Path, sampleName(p.Kind)), p.Kind)
		} else {
			add(p.Path, p.Kind)
		}
	}
	for _, rel := range sortedKeys(homeFiles) {
		add(filepath.Join(env.Home, filepath.FromSlash(rel)), homeFiles[rel])
	}
	for _, rel := range sortedKeys(homeDirs) {
		add(filepath.Join(env.Home, filepath.FromSlash(rel), sampleName(homeDirs[rel])), homeDirs[rel])
	}
	if project != "" {
		add(filepath.Join(project, ".env"), KindEnvFile)
		add(filepath.Join(project, "deploy"+keyExts[0]), KindPrivateKey)
	}
	return out
}

// sampleName is a file name to put in a credential dir of the kind.
func sampleName(kind string) string {
	if kind == KindSSH {
		return keyNames[len(keyNames)-1] // id_ed25519, the usual key name
	}
	return "credentials"
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
