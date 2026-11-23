package credmeta

import (
	"path/filepath"
	"testing"

	"github.com/nickelsec/jarx/internal/platform"
)

func fakeEnv(t *testing.T, jarxEnv string) platform.Env {
	t.Helper()
	home := t.TempDir()
	if jarxEnv != "" {
		writeFile(t, filepath.Join(home, platform.JarxEnvName), jarxEnv)
	}
	env, err := platform.FromHome(home)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestCredentialLocations(t *testing.T) {
	env := fakeEnv(t, "")
	h := func(rel string) string { return filepath.Join(env.Home, filepath.FromSlash(rel)) }
	for path, want := range map[string]string{
		h("proj/.env"):                   "env_file",
		h("proj/.env.local"):             "env_file",
		h("proj/.npmrc"):                 "npmrc",
		h("proj/config/.env.production"): "env_file",
		h(".ssh/id_ed25519"):             "ssh",
		h(".ssh/config"):                 "ssh",
		h(".SSH/config"):                 "ssh", // same dir on Windows and macOS
		h("proj/.ENV"):                   "env_file",
		h("proj/deploy/id_rsa"):          "private_key",
		h("proj/certs/server.pem"):       "private_key",
		h("proj/certs/server.KEY"):       "private_key",
		h("proj/signing.p12"):            "private_key",
		h(".aws/credentials"):            "aws",
		h(".netrc"):                      "netrc",
		h("_netrc"):                      "netrc",
		h(".git-credentials"):            "git_credentials",
		h(".docker/config.json"):         "docker",
		h(".kube/config"):                "kube",
		h(".npmrc"):                      "npmrc",
		h(".pypirc"):                     "pypirc",
		h(".config/gh/hosts.yml"):        "gh",
		h(".config/gcloud/application_default_credentials.json"): "gcloud",
		h(".azure/msal_token_cache.json"):                        "azure",
		h(".gnupg/private-keys-v1.d/x.key"):                      "gnupg",
		h(".claude/.credentials.json"):                           "claude_login",
		h(".codex/auth.json"):                                    "codex_login",
	} {
		got, ok := Location(env, path)
		if !ok || got != want {
			t.Errorf("Location(%s) = %q, %v; want %q", path, got, ok, want)
		}
	}
}

func TestOrdinaryFilesAreNotCredentials(t *testing.T) {
	env := fakeEnv(t, "")
	h := func(rel string) string { return filepath.Join(env.Home, filepath.FromSlash(rel)) }
	for _, path := range []string{
		h("proj/CLAUDE.md"),
		h("proj/README.md"),
		h("proj/environment.md"),
		h("proj/.envrc.md"),
		h("proj/keys.md"),
		h("proj/docs/ssh.md"),
		h(".claude/CLAUDE.md"),
		h(".aws-notes.md"),
		h("proj/.ssh-guide/notes.md"),
	} {
		if kind, ok := Location(env, path); ok {
			t.Errorf("Location(%s) = %q, want not a credential", path, kind)
		}
	}
}

func TestAgentLoginFilesFollowTheirConfigDirs(t *testing.T) {
	env := fakeEnv(t, "CLAUDE_CONFIG_DIR=/cfg/claude\nCODEX_HOME=/cfg/codex\n")
	for path, want := range map[string]string{
		env.MapPath("/cfg/claude/.credentials.json"): "claude_login",
		env.MapPath("/cfg/codex/auth.json"):          "codex_login",
	} {
		if got, ok := Location(env, path); !ok || got != want {
			t.Errorf("Location(%s) = %q, %v; want %q", path, got, ok, want)
		}
	}
}

func TestLocateGivesThePathInsideThePlace(t *testing.T) {
	env := fakeEnv(t, "AWS_SHARED_CREDENTIALS_FILE=/a/creds\n")
	h := func(rel string) string { return filepath.Join(env.Home, filepath.FromSlash(rel)) }
	for path, want := range map[string]Located{
		h(".config/gcloud/application_default_credentials.json"): {KindGcloud, "application_default_credentials.json", false},
		h(".aws/sso/cache/abc.json"):                             {KindAWS, "abc.json", false},
		h(".aws/cli/cache/abc.json"):                             {KindAWS, "abc.json", false},
		h(".aws/config"):                                         {KindAWS, "config", true},
		h(".aws/credentials"):                                    {KindAWS, "credentials", true},
		env.MapPath("/a/creds"):                                  {KindAWS, "creds", true},
		h(".ssh/id_ed25519"):                                     {KindSSH, "id_ed25519", true},
		h("proj/.env.local"):                                     {KindEnvFile, ".env.local", true},
		h("proj/certs/server.pem"):                               {KindPrivateKey, "server.pem", false},
		h(".azure/msal_token_cache.json"):                        {KindAzure, "msal_token_cache.json", false},
	} {
		if got, ok := Locate(env, path); !ok || got != want {
			t.Errorf("Locate(%s) = %+v, %v; want %+v", path, got, ok, want)
		}
	}
	if _, ok := Locate(env, h("proj/README.md")); ok {
		t.Error("Locate(README.md) found a credential")
	}
}
