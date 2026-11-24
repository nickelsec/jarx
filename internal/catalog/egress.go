package catalog

import "github.com/nickelsec/jarx/internal/model"

// EgressVar is an env var that says where an agent talks to. Its value is
// a URL, a path or a switch, never a secret, so jarx may keep it (masked,
// like any text). From the Claude Code env vars docs, checked 2026-11-24.
type EgressVar struct {
	Name string
	Area model.EgressArea
}

// claudeEgressVars are the Claude Code env vars that set its model
// endpoint, proxy and TLS. Credentials (API keys, tokens, the client key
// passphrase) aren't here: jarx only notes whether those are set.
//
//nolint:gochecknoglobals // fixed table, read only
var claudeEgressVars = []EgressVar{
	{"ANTHROPIC_BASE_URL", model.AreaModel},
	{"ANTHROPIC_BEDROCK_BASE_URL", model.AreaModel},
	{"ANTHROPIC_BEDROCK_MANTLE_BASE_URL", model.AreaModel},
	{"ANTHROPIC_VERTEX_BASE_URL", model.AreaModel},
	{"ANTHROPIC_FOUNDRY_BASE_URL", model.AreaModel},
	{"ANTHROPIC_GOOGLE_CLOUD_BASE_URL", model.AreaModel},
	{"ANTHROPIC_AWS_BASE_URL", model.AreaModel},
	{"CLAUDE_CODE_USE_BEDROCK", model.AreaModel},
	{"CLAUDE_CODE_USE_VERTEX", model.AreaModel},
	{"CLAUDE_CODE_USE_FOUNDRY", model.AreaModel},
	{"HTTPS_PROXY", model.AreaProxy},
	{"HTTP_PROXY", model.AreaProxy},
	{"NO_PROXY", model.AreaProxy},
	{"NODE_EXTRA_CA_CERTS", model.AreaTLS},
	{"CLAUDE_CODE_CERT_STORE", model.AreaTLS},
	{"CLAUDE_CODE_CLIENT_CERT", model.AreaTLS},
	{"CLAUDE_CODE_CLIENT_KEY", model.AreaTLS},
}

// claudeAuthVars are the Claude Code env vars that hold a credential.
// jarx only notes that one is set, never its value.
//
//nolint:gochecknoglobals // fixed list, read only
var claudeAuthVars = []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_FOUNDRY_API_KEY", "ANTHROPIC_AWS_API_KEY"}

// ClaudeEgressVars returns claudeEgressVars.
func ClaudeEgressVars() []EgressVar { return append([]EgressVar(nil), claudeEgressVars...) }

// ClaudeAuthVars returns claudeAuthVars.
func ClaudeAuthVars() []string { return append([]string(nil), claudeAuthVars...) }

// EgressVarArea is the area of a Claude egress env var, and whether it is
// one.
func EgressVarArea(name string) (model.EgressArea, bool) {
	for _, v := range claudeEgressVars {
		if v.Name == name {
			return v.Area, true
		}
	}
	return "", false
}
