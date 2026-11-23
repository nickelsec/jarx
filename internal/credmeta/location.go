// Package credmeta knows where credentials live and, from phase 5, reads the
// safe metadata about them. It never reads a credential value.
//
// Location is the first piece: other packages ask it before reading a path
// someone else chose (like the target of a CLAUDE.md @import), so jarx never
// opens a credential file by following a pointer to it.
package credmeta

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/platform"
)

// homeFiles are credential files at a fixed place under the home dir,
// keyed by slash path relative to it.
//
//nolint:gochecknoglobals // fixed list, read only
var homeFiles = map[string]string{
	".aws/credentials":     "aws",
	".netrc":               "netrc",
	"_netrc":               "netrc",
	".git-credentials":     "git_credentials",
	".docker/config.json":  "docker",
	".kube/config":         "kube",
	".npmrc":               "npmrc",
	".pypirc":              "pypirc",
	".config/gh/hosts.yml": "gh",
}

// homeDirs are dirs under the home dir where every file counts.
//
//nolint:gochecknoglobals // fixed list, read only
var homeDirs = map[string]string{
	".ssh":           "ssh",
	".gnupg":         "gnupg",
	".azure":         "azure",
	".config/gcloud": "gcloud",
}

// keyNames and keyExts mark private keys anywhere.
//
//nolint:gochecknoglobals // fixed list, read only
var (
	keyNames = []string{"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
	keyExts  = []string{".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk"}
)

// Location says whether path is a credential location, and which kind. It
// only looks at the path, never at the file.
func Location(env platform.Env, path string) (string, bool) {
	p := normalize(env, path)
	for _, check := range []func(platform.Env, string) (string, bool){loginFile, homeLocation, byName} {
		if kind, ok := check(env, p); ok {
			return kind, true
		}
	}
	return "", false
}

// normalize cleans p and lowercases it on every OS. Windows and the default
// macOS file system ignore case, so ~/.SSH is ~/.ssh there, and a key named
// server.KEY is a key anywhere. On Linux this can match a file that isn't a
// credential; refusing to read one of those is the safe mistake.
func normalize(_ platform.Env, p string) string {
	return strings.ToLower(filepath.Clean(p))
}

// loginFile matches the agents' own login files.
func loginFile(env platform.Env, p string) (string, bool) {
	switch p {
	case normalize(env, filepath.Join(configDir(env, "CLAUDE_CONFIG_DIR", ".claude"), ".credentials.json")):
		return "claude_login", true
	case normalize(env, filepath.Join(configDir(env, "CODEX_HOME", ".codex"), "auth.json")):
		return "codex_login", true
	}
	return "", false
}

// homeLocation matches the fixed credential files and dirs under the home.
func homeLocation(env platform.Env, p string) (string, bool) {
	rel, err := filepath.Rel(normalize(env, env.Home), p)
	if err != nil || !filepath.IsLocal(rel) {
		return "", false
	}
	rel = filepath.ToSlash(rel)
	if kind, ok := homeFiles[rel]; ok {
		return kind, true
	}
	for dir, kind := range homeDirs {
		if strings.HasPrefix(rel, dir+"/") {
			return kind, true
		}
	}
	return "", false
}

// byName matches .env files and private keys anywhere.
func byName(_ platform.Env, p string) (string, bool) {
	base := filepath.Base(p)
	switch {
	case base == ".env" || strings.HasPrefix(base, ".env."):
		return "env_file", true
	case slices.Contains(keyNames, base), slices.Contains(keyExts, filepath.Ext(base)):
		return "private_key", true
	}
	return "", false
}

// configDir is an agent's config dir: the env var's dir when set, or
// <home>/<fallback>.
func configDir(env platform.Env, envVar, fallback string) string {
	if dir, ok := env.Lookup(envVar); ok && dir != "" {
		return env.MapPath(dir)
	}
	return filepath.Join(env.Home, fallback)
}
