package credmeta

// The kinds of credential location.
const (
	KindAWS         = "aws"
	KindGH          = "gh"
	KindGcloud      = "gcloud"
	KindAzure       = "azure"
	KindDocker      = "docker"
	KindKube        = "kube"
	KindSSH         = "ssh"
	KindGit         = "git_credentials"
	KindNetrc       = "netrc"
	KindNpm         = "npmrc"
	KindPypi        = "pypirc"
	KindGnupg       = "gnupg"
	KindClaudeLogin = "claude_login"
	KindCodexLogin  = "codex_login"
	KindEnvFile     = "env_file"
	KindPrivateKey  = "private_key"
	KindEnvVar      = "env_var" // a secret-looking env var, by name only
	// KindSecretInText is a secret pasted into text the agent loads, and
	// KindInlineSecret one written into an MCP server's definition. Both
	// are known by kind and fingerprint, never by value.
	KindSecretInText = "secret_in_text"
	// KindSecretInHistory is a secret that ended up in one of the agent's
	// own sessions: it went through the agent, so the agent saw it.
	KindSecretInHistory = "secret_in_history"
	KindInlineSecret    = "inline_secret"
)

const goosWindows = "windows"

// keyPassword is a key name several formats use for a secret.
const keyPassword = "password"
