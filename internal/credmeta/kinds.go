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
)

const goosWindows = "windows"

// keyPassword is a key name several formats use for a secret.
const keyPassword = "password"
