package probe

import (
	"regexp"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/model"
)

// Claude's ${VAR} expansion, from code.claude.com/docs/en/mcp
// (#environment-variable-expansion-in-mcp-json): ${VAR} and ${VAR:-default}
// in command, args, env, url and headers. A variable that's unset with no
// default stays as written (and Claude warns); an empty one counts as set.
// ${CLAUDE_PROJECT_DIR} and ${CLAUDE_PLUGIN_ROOT} are the project and plugin
// dirs.
//
// In a remote server's url and headers, credential variables read as empty,
// whether set or not, and their default is ignored. The docs name examples
// (ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN, AWS_BEARER_TOKEN_BEDROCK,
// HTTPS_PROXY, NPM_TOKEN) and the families they come from, not a full list.
// jarx reads those families as empty too, so it never sends a server a
// credential Claude would hold back. Provider base URLs still expand.

var varRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}`)

// credentialNames are the documented examples; credentialPrefixes are the
// families they come from: Claude's own, the cloud providers' and proxies.
//
//nolint:gochecknoglobals // fixed lists, read only
var (
	credentialNames    = []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "AWS_BEARER_TOKEN_BEDROCK", "HTTPS_PROXY", "NPM_TOKEN"}
	credentialPrefixes = []string{"ANTHROPIC_", "CLAUDE_CODE_", "AWS_", "GOOGLE_", "CLOUDSDK_", "AZURE_", "VERTEX_"}
)

// readsEmpty says whether a variable reads as empty toward a remote server.
func readsEmpty(name string) bool {
	upper := strings.ToUpper(name)
	switch {
	case strings.HasSuffix(upper, "_BASE_URL"):
		return false // provider base URLs still expand
	case slices.Contains(credentialNames, upper), strings.HasSuffix(upper, "_PROXY"):
		return true
	}
	for _, p := range credentialPrefixes {
		if strings.HasPrefix(upper, p) {
			return true
		}
	}
	return false
}

// expandClaude expands s the way Claude does, and returns the variables it
// left as written because they're unset with no default. remote is for a
// remote server's url and headers.
func expandClaude(s string, lookup func(string) (string, bool), spec model.LaunchSpec, remote bool) (string, []string) {
	var missing []string
	out := varRef.ReplaceAllStringFunc(s, func(ref string) string {
		m := varRef.FindStringSubmatch(ref)
		name, hasDefault, def := m[1], m[2] != "", m[3]
		if dir := pathVar(name, spec); dir != "" {
			return dir
		}
		if remote && readsEmpty(name) {
			return ""
		}
		if v, ok := lookup(name); ok {
			return v
		}
		if hasDefault {
			return def
		}
		missing = append(missing, name)
		return ref
	})
	return out, missing
}

// pathVar is what one of Claude's path variables points at, or "".
func pathVar(name string, spec model.LaunchSpec) string {
	switch name {
	case "CLAUDE_PROJECT_DIR":
		return spec.ProjectDir
	case "CLAUDE_PLUGIN_ROOT":
		return spec.PluginRoot
	case "CLAUDE_PLUGIN_DATA":
		return spec.PluginData
	}
	return ""
}
