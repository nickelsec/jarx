package report

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/model"
)

func (f scanFixture) cred(kind, rel string, read model.ReadStatus, via string, facts ...[2]string) model.Credential {
	cr := model.Credential{Kind: model.CredentialKind(kind), Path: f.path(rel), Read: read}
	if via != "" {
		cr.Via = f.text(via)
	}
	for _, fa := range facts {
		cr.Facts = append(cr.Facts, model.Pair{Key: f.text(fa[0]), Value: f.text(fa[1])})
	}
	return cr
}

func TestCredentialLocationsAreCountedWithWhatCouldntBeRead(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.Credentials = []model.Credential{
		f.cred("aws", ".aws/credentials", model.ReadOK, "default", [2]string{"profile dev", "static keys"}),
		f.cred("gh", ".config/gh/hosts.yml", model.ReadFailed, "default"),
	}
	v.Projects[0].Credentials = []model.Credential{f.cred("env_file", "app/.env", model.ReadOK, "", [2]string{"key", "API_KEY"})}

	out := render(Style{Width: 80}, v)

	if want := "+- 3 credential locations            1 couldn't read\n"; !strings.Contains(out, want) {
		t.Errorf("output =\n%s\nwant the scanned row %q", out, want)
	}
}

func TestTheInventoryListsEachCredentialWithItsFacts(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.All = true
	v.Credentials = []model.Credential{
		f.cred("aws", ".aws/credentials", model.ReadOK, "default", [2]string{"profile dev", "static keys"}, [2]string{"profile ci", ""}),
		f.cred("gh", "cfg/gh/hosts.yml", model.ReadOK, "GH_CONFIG_DIR", [2]string{"host github.com", "user octocat, no token in the file"}),
		f.cred("claude_login", ".claude/.credentials.json", model.ReadExistsOnly, "default"),
	}
	v.Projects[0].Credentials = []model.Credential{f.cred("env_file", "app/.env", model.ReadOK, "", [2]string{"key", "API_KEY"}, [2]string{"key", "DB_URL"})}

	out := render(Style{Width: 200}, v)

	for _, want := range []string{
		"credentials (3)\n",
		"  aws  " + filepath.FromSlash("~/.aws/credentials") + "  profile dev: static keys; profile ci\n",
		"  gh  " + filepath.FromSlash("~/cfg/gh/hosts.yml") + "  via GH_CONFIG_DIR  host github.com: user octocat, no token in the file\n",
		"  claude_login  " + filepath.FromSlash("~/.claude/.credentials.json") + "  existence only\n",
		"    credentials\n      env_file  " + filepath.FromSlash("~/app/.env") + "  key: API_KEY; key: DB_URL\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output =\n%s\nwant it to contain %q", out, want)
		}
	}
}
