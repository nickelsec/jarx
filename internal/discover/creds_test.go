package discover

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
)

// legacyKey is a made-up legacy PEM key with a passphrase. The armor is
// put together here so nothing in the repo reads as a private key.
var legacyKey = "-----BEGIN " + "RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nSkFSWC1DQU5BUlktS0VZ\n-----END " + "RSA PRIVATE KEY-----\n" //nolint:gochecknoglobals // a fixture

func credContext(t *testing.T, jarxEnv string) agent.Context {
	t.Helper()
	home := t.TempDir()
	if jarxEnv != "" {
		writeFile(t, filepath.Join(home, platform.JarxEnvName), jarxEnv)
	}
	env, err := platform.FromHome(home)
	if err != nil {
		t.Fatal(err)
	}
	f, err := fsys.New(env)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	s, err := redact.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return agent.Context{Env: env, Files: f, Scrub: s}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// credLines is each credential as "path [read] via: facts", with paths
// relative to the home.
func credLines(c agent.Context, cs []model.Credential) []string {
	out := make([]string, 0, len(cs))
	for _, cr := range cs {
		rel, _ := filepath.Rel(c.Env.Home, cr.Path.Raw())
		if cr.Path.IsZero() {
			rel = cr.Name.String() // an env var has a name, not a path
		}
		facts := make([]string, 0, len(cr.Facts))
		for _, f := range cr.Facts {
			facts = append(facts, f.Key.String()+"="+f.Value.String())
		}
		out = append(out, fmt.Sprintf("%s %s [%s] via %s: %s", cr.Kind, filepath.ToSlash(rel), cr.Read, cr.Via, strings.Join(facts, ", ")))
	}
	return out
}

func TestTheMachinesCredentialsAreFoundWithTheirSafeMetadata(t *testing.T) {
	c := credContext(t, "")
	h := func(rel string) string { return filepath.Join(c.Env.Home, filepath.FromSlash(rel)) }
	writeFile(t, h(".aws/credentials"), "[dev]\naws_access_key_id = JARX-CANARY-1\naws_secret_access_key = JARX-CANARY-2\n")
	writeFile(t, h(".aws/sso/cache/token.json"), `{"accessToken": "JARX-CANARY-3"}`)
	writeFile(t, h(".ssh/id_rsa"), legacyKey)
	writeFile(t, h(".ssh/id_rsa.pub"), "ssh-rsa AAAA fake@demo\n")
	writeFile(t, h(".ssh/config"), "Host x\n")
	writeFile(t, h(".ssh/known_hosts"), "x ssh-rsa AAAA\n")
	writeFile(t, h(".config/gcloud/application_default_credentials.json"), `{"refresh_token": "JARX-CANARY-4"}`)
	writeFile(t, h(".config/gcloud/logs/x.log"), "log")
	writeFile(t, h(".claude/.credentials.json"), `{"token": "JARX-CANARY-5"}`)

	r := Run(c, nil, nil)

	want := []string{
		"aws .aws/credentials [read] via default: profile dev=static keys",
		"aws .aws/sso/cache [existence only] via default: files=1",
		"gcloud .config/gcloud [existence only] via default: files=2",
		"ssh .ssh/id_rsa [read] via default: type=rsa, passphrase=yes",
		"claude_login .claude/.credentials.json [existence only] via default: ",
	}
	if got := credLines(c, r.Credentials); !slices.Equal(got, want) {
		t.Errorf("credentials =\n  %q\nwant\n  %q", got, want)
	}
	if strings.Contains(fmt.Sprintf("%+v", r), "CANARY") {
		t.Error("the scan result holds a secret from a credential file")
	}
}

func TestACredentialThatWontParseSaysSoAndNothingMore(t *testing.T) {
	c := credContext(t, "")
	writeFile(t, filepath.Join(c.Env.Home, ".docker", "config.json"), `{"auths": {"x": JARX-CANARY}}`)

	r := Run(c, nil, nil)

	if len(r.Credentials) != 1 || r.Credentials[0].Read != model.ReadFailed || len(r.Credentials[0].Facts) != 0 {
		t.Fatalf("credentials = %q, want the docker file as couldn't read, with no parser error text", credLines(c, r.Credentials))
	}
}

func TestCredentialsFollowTheEnvVarsThatMoveThem(t *testing.T) {
	c := credContext(t, "GH_CONFIG_DIR=/cfg/gh\n")
	writeFile(t, c.Env.MapPath("/cfg/gh/hosts.yml"), "github.com:\n    user: octocat\n    oauth_token: JARX-CANARY\n")

	r := Run(c, nil, nil)

	if got, want := credLines(c, r.Credentials), []string{"gh cfg/gh/hosts.yml [read] via GH_CONFIG_DIR: host github.com=user octocat, token in the file"}; !slices.Equal(got, want) {
		t.Errorf("credentials = %q, want %q", got, want)
	}
}

func TestAProjectsOwnCredentialFilesAreOnTheProject(t *testing.T) {
	c := credContext(t, "")
	proj := filepath.Join(c.Env.Home, "proj")
	writeFile(t, filepath.Join(proj, ".env"), "API_KEY=JARX-CANARY-1\n")
	writeFile(t, filepath.Join(proj, ".npmrc"), "//npm.example.com/:_authToken=JARX-CANARY-2\n")
	writeFile(t, filepath.Join(proj, "certs", "deploy.pem"), "JARX-CANARY-3")
	writeFile(t, filepath.Join(proj, "README.md"), "hi")

	r := Run(c, []agent.Adapter{fakeAdapter{name: model.AgentClaude, paths: []string{proj}}}, nil)

	want := []string{
		"env_file proj/.env [read] via : key=API_KEY",
		"npmrc proj/.npmrc [read] via : registry npm.example.com/=_authToken",
		"private_key proj/certs/deploy.pem [existence only] via : ",
	}
	if len(r.Projects) != 1 {
		t.Fatalf("projects = %d, want 1", len(r.Projects))
	}
	if got := credLines(c, r.Projects[0].Credentials); !slices.Equal(got, want) {
		t.Errorf("project credentials =\n  %q\nwant\n  %q", got, want)
	}
	if strings.Contains(fmt.Sprintf("%+v", r), "CANARY") {
		t.Error("the scan result holds a secret from a credential file")
	}
}

func TestSecretLookingEnvVarsAreCredentialsByNameOnly(t *testing.T) {
	c := credContext(t, "GITHUB_TOKEN=JARX-CANARY-1\nEDITOR=vim\nOPENAI_API_KEY=JARX-CANARY-2\nTOKEN_PATH=/tmp/x\n")

	r := Run(c, nil, nil)

	want := []string{
		"env_var GITHUB_TOKEN [existence only] via environment: ",
		"env_var OPENAI_API_KEY [existence only] via environment: ",
	}
	if got := credLines(c, r.Credentials); !slices.Equal(got, want) {
		t.Errorf("credentials = %q, want %q", got, want)
	}
	if strings.Contains(fmt.Sprintf("%+v", r), "CANARY") {
		t.Error("an env var's value reached the scan result")
	}
}
