package credmeta

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestEverySampleIsALocationOfItsKind(t *testing.T) {
	// Samples and Location share one list, so they can't drift apart.
	env := fakeEnv(t, "")
	for _, s := range Samples(env, filepath.Join(env.Home, "code", "app")) {
		if kind, ok := Location(env, s.Path); !ok || kind != s.Kind {
			t.Errorf("Location(%s) = %q, %v; want %q", s.Path, kind, ok, s.Kind)
		}
	}
}

func TestSamplesCoverEveryKind(t *testing.T) {
	env := fakeEnv(t, "")
	got := map[string]bool{}
	for _, s := range Samples(env, filepath.Join(env.Home, "code", "app")) {
		got[s.Kind] = true
	}
	want := make([]string, 0, 4+len(homeFiles)+len(homeDirs))
	want = append(want, "claude_login", "codex_login", "env_file", "private_key")
	for _, k := range homeFiles {
		want = append(want, k)
	}
	for _, k := range homeDirs {
		want = append(want, k)
	}
	for _, k := range want {
		if !got[k] {
			t.Errorf("no sample of kind %s", k)
		}
	}
}

func TestAProjectAddsItsOwnEnvFile(t *testing.T) {
	env := fakeEnv(t, "")
	proj := filepath.Join(env.Home, "code", "app")
	paths := func(dir string) []string {
		ss := Samples(env, dir)
		out := make([]string, 0, len(ss))
		for _, s := range ss {
			out = append(out, s.Path)
		}
		return out
	}

	if !slices.Contains(paths(proj), filepath.Join(proj, ".env")) {
		t.Errorf("samples = %q, want the project's .env", paths(proj))
	}
	if slices.Contains(paths(""), filepath.Join(proj, ".env")) {
		t.Errorf("samples with no project = %q, want no project files", paths(""))
	}
}

func TestSamplesFollowPlaces(t *testing.T) {
	env := fakeEnv(t, "APPDATA=/appdata\nKUBECONFIG=/k/a\n")
	env.GOOS = "windows"
	got := map[string]string{}
	for _, s := range Samples(env, "") {
		got[s.Path] = s.Kind
	}
	for path, kind := range map[string]string{
		env.MapPath("/appdata/GitHub CLI/hosts.yml"):   "gh",
		env.MapPath("/appdata/gcloud/credentials"):     "gcloud",
		env.MapPath("/k/a"):                            "kube",
		filepath.Join(env.Home, ".aws", "credentials"): "aws",
	} {
		if got[path] != kind {
			t.Errorf("Samples has %s as %q, want %q", path, got[path], kind)
		}
	}
}
