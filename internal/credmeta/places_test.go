package credmeta

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/platform"
)

// placesOf is every path Places gives for kind, with how each was chosen.
func placesOf(env platform.Env, kind string) []string {
	var out []string
	for _, p := range Places(env) {
		if p.Kind == kind {
			out = append(out, p.Path+" via "+p.Via)
		}
	}
	return out
}

func TestPlacesFollowEachCLIsDocs(t *testing.T) {
	for name, tc := range map[string]struct {
		goos, vars, kind string
		want             []string // home-relative slash paths, or /abs for a mapped var, then "via ..."
	}{
		"gh unix default":   {"linux", "", "gh", []string{"~/.config/gh/hosts.yml via default"}},
		"gh windows":        {"windows", "APPDATA=/appdata\n", "gh", []string{"/appdata/GitHub CLI/hosts.yml via AppData"}},
		"gh windows no var": {"windows", "", "gh", []string{"~/.config/gh/hosts.yml via default"}},
		"gh xdg wins":       {"windows", "APPDATA=/appdata\nXDG_CONFIG_HOME=/xdg\n", "gh", []string{"/xdg/gh/hosts.yml via XDG_CONFIG_HOME"}},
		"gh config dir":     {"linux", "XDG_CONFIG_HOME=/xdg\nGH_CONFIG_DIR=/ghc\n", "gh", []string{"/ghc/hosts.yml via GH_CONFIG_DIR"}},
		"gcloud unix":       {"darwin", "", "gcloud", []string{"~/.config/gcloud via default"}},
		"gcloud windows":    {"windows", "APPDATA=/appdata\n", "gcloud", []string{"/appdata/gcloud via APPDATA"}},
		"gcloud var":        {"windows", "APPDATA=/appdata\nCLOUDSDK_CONFIG=/gc\n", "gcloud", []string{"/gc via CLOUDSDK_CONFIG"}},
		"gcloud adc var": {"linux", "GOOGLE_APPLICATION_CREDENTIALS=/sa/key.json\n", "gcloud", []string{
			"~/.config/gcloud via default", "/sa/key.json via GOOGLE_APPLICATION_CREDENTIALS",
		}},
		"aws default": {"linux", "", "aws", []string{
			"~/.aws/credentials via default", "~/.aws/config via default", "~/.aws/sso/cache via default", "~/.aws/cli/cache via default",
		}},
		"aws vars": {"linux", "AWS_CONFIG_FILE=/a/conf\nAWS_SHARED_CREDENTIALS_FILE=/a/creds\n", "aws", []string{
			"/a/creds via AWS_SHARED_CREDENTIALS_FILE", "/a/conf via AWS_CONFIG_FILE", "~/.aws/sso/cache via default", "~/.aws/cli/cache via default",
		}},
		"azure":          {"linux", "AZURE_CONFIG_DIR=/az\n", "azure", []string{"/az via AZURE_CONFIG_DIR"}},
		"docker default": {"windows", "", "docker", []string{"~/.docker/config.json via default"}},
		"docker var":     {"linux", "DOCKER_CONFIG=/dk\n", "docker", []string{"/dk/config.json via DOCKER_CONFIG"}},
		"kube default":   {"linux", "", "kube", []string{"~/.kube/config via default"}},
		"kube list unix": {"linux", "KUBECONFIG=/k/a:/k/b\n", "kube", []string{"/k/a via KUBECONFIG", "/k/b via KUBECONFIG"}},
		"kube list win":  {"windows", "KUBECONFIG=/k/a;/k/b\n", "kube", []string{"/k/a via KUBECONFIG", "/k/b via KUBECONFIG"}},
		"ssh":            {"windows", "", "ssh", []string{"~/.ssh via default"}},
		"git default":    {"linux", "", "git_credentials", []string{"~/.git-credentials via default", "~/.config/git/credentials via default"}},
		"git xdg":        {"linux", "XDG_CONFIG_HOME=/xdg\n", "git_credentials", []string{"~/.git-credentials via default", "/xdg/git/credentials via XDG_CONFIG_HOME"}},
		"netrc unix":     {"linux", "", "netrc", []string{"~/.netrc via default"}},
		"netrc windows":  {"windows", "", "netrc", []string{"~/.netrc via default", "~/_netrc via default"}},
		"netrc var":      {"windows", "NETRC=/n/rc\n", "netrc", []string{"/n/rc via NETRC"}},
		"npm":            {"linux", "NPM_CONFIG_USERCONFIG=/npm/rc\n", "npmrc", []string{"/npm/rc via NPM_CONFIG_USERCONFIG"}},
		"pypi":           {"windows", "", "pypirc", []string{"~/.pypirc via default"}},
		"gnupg":          {"linux", "GNUPGHOME=/gpg\n", "gnupg", []string{"/gpg via GNUPGHOME"}},
		"claude login":   {"linux", "CLAUDE_CONFIG_DIR=/cc\n", "claude_login", []string{"/cc/.credentials.json via CLAUDE_CONFIG_DIR"}},
		"codex login":    {"linux", "", "codex_login", []string{"~/.codex/auth.json via default"}},
	} {
		t.Run(name, func(t *testing.T) {
			env := fakeEnv(t, tc.vars)
			env.GOOS = tc.goos
			want := make([]string, 0, len(tc.want))
			for _, w := range tc.want {
				path, via, _ := strings.Cut(w, " via ")
				if rest, ok := strings.CutPrefix(path, "~/"); ok {
					path = filepath.Join(env.Home, filepath.FromSlash(rest))
				} else {
					path = env.MapPath(path)
				}
				want = append(want, path+" via "+via)
			}
			if got := placesOf(env, tc.kind); !slices.Equal(got, want) {
				t.Errorf("places = %q, want %q", got, want)
			}
		})
	}
}

func TestEveryPlaceIsACredentialLocation(t *testing.T) {
	env := fakeEnv(t, "GH_CONFIG_DIR=/ghc\nCLOUDSDK_CONFIG=/gc\nAWS_SHARED_CREDENTIALS_FILE=/a/creds\nKUBECONFIG=/k/a\nNETRC=/n/rc\nDOCKER_CONFIG=/dk\nGNUPGHOME=/gpg\nAZURE_CONFIG_DIR=/az\nNPM_CONFIG_USERCONFIG=/npm/rc\n")
	for _, p := range Places(env) {
		path := p.Path
		if p.Dir {
			path = filepath.Join(path, "some-file")
		}
		if kind, ok := Location(env, path); !ok || kind != p.Kind {
			t.Errorf("Location(%s) = %q, %v; want %q, the read guard must refuse every place", path, kind, ok, p.Kind)
		}
	}
}

func TestDefaultPlacesStayGuardedWhenAVarMovesThem(t *testing.T) {
	env := fakeEnv(t, "GH_CONFIG_DIR=/ghc\nAWS_SHARED_CREDENTIALS_FILE=/a/creds\n")
	for _, rel := range []string{".config/gh/hosts.yml", ".aws/credentials"} {
		path := filepath.Join(env.Home, filepath.FromSlash(rel))
		if _, ok := Location(env, path); !ok {
			t.Errorf("Location(%s) = not a credential; a moved default may still hold an old secret", path)
		}
	}
}
