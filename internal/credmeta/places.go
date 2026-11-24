package credmeta

import (
	"path/filepath"
	"strings"

	"github.com/nickelsec/jarx/internal/platform"
)

// Place is where one kind of credential lives on this machine, from the
// CLI's own docs (the table in design.md, "Where credentials live and what
// jarx reads").
type Place struct {
	Kind string
	Path string
	Dir  bool   // every file under Path counts
	Via  string // the env var that chose Path, or "default"
	// NoRead marks a place that's only checked for existence, like a token
	// cache, even when its kind has a parser.
	NoRead bool
}

const viaDefault = "default"

// Places is every credential place for env's OS and env vars, in the order
// each CLI looks.
func Places(env platform.Env) []Place {
	kinds := []func(platform.Env) []Place{
		awsPlaces, ghPlaces, gcloudPlaces, azurePlaces, dockerPlaces, kubePlaces, sshPlaces,
		gitPlaces, netrcPlaces, npmPlaces, pypiPlaces, gnupgPlaces, loginPlaces,
	}
	out := make([]Place, 0, len(kinds))
	for _, f := range kinds {
		out = append(out, f(env)...)
	}
	return out
}

func home(env platform.Env, rel string) string {
	return filepath.Join(env.Home, filepath.FromSlash(rel))
}

// fromVar is the var's value as a path when it's set and not empty.
func fromVar(env platform.Env, name string) (string, bool) {
	v, ok := env.Lookup(name)
	if !ok || v == "" {
		return "", false
	}
	return env.MapPath(v), true
}

// varOr is a place from the env var, else the default under the home.
func varOr(env platform.Env, kind, name, rel string, dir bool) Place {
	if p, ok := fromVar(env, name); ok {
		return Place{Kind: kind, Path: p, Dir: dir, Via: name}
	}
	return Place{Kind: kind, Path: home(env, rel), Dir: dir, Via: viaDefault}
}

func awsPlaces(env platform.Env) []Place {
	// The credentials file first: its keys win over the config file's.
	return []Place{
		varOr(env, KindAWS, "AWS_SHARED_CREDENTIALS_FILE", ".aws/credentials", false),
		varOr(env, KindAWS, "AWS_CONFIG_FILE", ".aws/config", false),
		{Kind: KindAWS, Path: home(env, ".aws/sso/cache"), Dir: true, Via: viaDefault, NoRead: true},
		{Kind: KindAWS, Path: home(env, ".aws/cli/cache"), Dir: true, Via: viaDefault, NoRead: true},
	}
}

// ghPlaces: GH_CONFIG_DIR, else $XDG_CONFIG_HOME/gh, else $AppData/GitHub
// CLI on Windows, else ~/.config/gh (gh help environment).
func ghPlaces(env platform.Env) []Place {
	dir, via := home(env, ".config/gh"), viaDefault
	if p, ok := fromVar(env, "GH_CONFIG_DIR"); ok {
		dir, via = p, "GH_CONFIG_DIR"
	} else if p, ok := fromVar(env, "XDG_CONFIG_HOME"); ok {
		dir, via = filepath.Join(p, "gh"), "XDG_CONFIG_HOME"
	} else if p, ok := fromVar(env, "AppData"); ok && env.GOOS == goosWindows {
		dir, via = filepath.Join(p, "GitHub CLI"), "AppData"
	}
	return []Place{{Kind: KindGH, Path: filepath.Join(dir, "hosts.yml"), Via: via}}
}

// gcloudPlaces: the config dir is CLOUDSDK_CONFIG, else %APPDATA%\gcloud
// on Windows, else ~/.config/gcloud ("Managing gcloud CLI configurations").
// Application Default Credentials are GOOGLE_APPLICATION_CREDENTIALS, and
// the file gcloud auth application-default login writes in the config dir
// ("How Application Default Credentials works"). The docs don't describe
// the files inside the config dir, so it's existence only.
func gcloudPlaces(env platform.Env) []Place {
	dir := Place{Kind: KindGcloud, Path: home(env, ".config/gcloud"), Dir: true, Via: viaDefault, NoRead: true}
	if p, ok := fromVar(env, "CLOUDSDK_CONFIG"); ok {
		dir.Path, dir.Via = p, "CLOUDSDK_CONFIG"
	} else if p, ok := fromVar(env, "APPDATA"); ok && env.GOOS == goosWindows {
		dir.Path, dir.Via = filepath.Join(p, "gcloud"), "APPDATA"
	}
	out := []Place{dir}
	if p, ok := fromVar(env, "GOOGLE_APPLICATION_CREDENTIALS"); ok {
		out = append(out, Place{Kind: KindGcloud, Path: p, Via: "GOOGLE_APPLICATION_CREDENTIALS", NoRead: true})
	}
	return out
}

func azurePlaces(env platform.Env) []Place {
	return []Place{varOr(env, KindAzure, "AZURE_CONFIG_DIR", ".azure", true)}
}

func dockerPlaces(env platform.Env) []Place {
	if p, ok := fromVar(env, "DOCKER_CONFIG"); ok {
		return []Place{{Kind: KindDocker, Path: filepath.Join(p, "config.json"), Via: "DOCKER_CONFIG"}}
	}
	return []Place{{Kind: KindDocker, Path: home(env, ".docker/config.json"), Via: viaDefault}}
}

// kubePlaces: KUBECONFIG is a list, ; on Windows and : elsewhere, and the
// files are merged; else ~/.kube/config.
func kubePlaces(env platform.Env) []Place {
	v, ok := env.Lookup("KUBECONFIG")
	if !ok || v == "" {
		return []Place{{Kind: KindKube, Path: home(env, ".kube/config"), Via: viaDefault}}
	}
	sep := ":"
	if env.GOOS == goosWindows {
		sep = ";"
	}
	var out []Place
	for p := range strings.SplitSeq(v, sep) {
		if p != "" {
			out = append(out, Place{Kind: KindKube, Path: env.MapPath(p), Via: "KUBECONFIG"})
		}
	}
	return out
}

func sshPlaces(env platform.Env) []Place {
	return []Place{{Kind: KindSSH, Path: home(env, ".ssh"), Dir: true, Via: viaDefault}}
}

// gitPlaces: git-credential-store reads both files.
func gitPlaces(env platform.Env) []Place {
	second := Place{Kind: KindGit, Path: home(env, ".config/git/credentials"), Via: viaDefault}
	if p, ok := fromVar(env, "XDG_CONFIG_HOME"); ok {
		second = Place{Kind: KindGit, Path: filepath.Join(p, "git", "credentials"), Via: "XDG_CONFIG_HOME"}
	}
	return []Place{{Kind: KindGit, Path: home(env, ".git-credentials"), Via: viaDefault}, second}
}

// netrcPlaces: NETRC wins (curl 8.16 and later); on Windows .netrc, then
// _netrc.
func netrcPlaces(env platform.Env) []Place {
	if p, ok := fromVar(env, "NETRC"); ok {
		return []Place{{Kind: KindNetrc, Path: p, Via: "NETRC"}}
	}
	out := []Place{{Kind: KindNetrc, Path: home(env, ".netrc"), Via: viaDefault}}
	if env.GOOS == goosWindows {
		out = append(out, Place{Kind: KindNetrc, Path: home(env, "_netrc"), Via: viaDefault})
	}
	return out
}

func npmPlaces(env platform.Env) []Place {
	return []Place{varOr(env, KindNpm, "NPM_CONFIG_USERCONFIG", ".npmrc", false)}
}

func pypiPlaces(env platform.Env) []Place {
	return []Place{{Kind: KindPypi, Path: home(env, ".pypirc"), Via: viaDefault}}
}

func gnupgPlaces(env platform.Env) []Place {
	return []Place{varOr(env, KindGnupg, "GNUPGHOME", ".gnupg", true)}
}

func loginPlaces(env platform.Env) []Place {
	login := func(kind, name, fallback, file string) Place {
		p := varOr(env, kind, name, fallback, false)
		p.Path = filepath.Join(p.Path, file)
		return p
	}
	return []Place{
		login(KindClaudeLogin, "CLAUDE_CONFIG_DIR", ".claude", ".credentials.json"),
		login(KindCodexLogin, "CODEX_HOME", ".codex", "auth.json"),
	}
}
