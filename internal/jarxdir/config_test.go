package jarxdir

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/platform"
)

func TestLoadConfigWithNothingSavedIsEmptyAndCreatesNothing(t *testing.T) {
	env, err := platform.FromHome(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(env)

	if err != nil || len(cfg.Repos) != 0 {
		t.Errorf("LoadConfig() = %+v, %v; want an empty config", cfg, err)
	}
	if _, err := os.Stat(env.StateDir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("LoadConfig created the state dir (stat err %v), want it to write nothing", err)
	}
}

func TestSaveThenLoadConfig(t *testing.T) {
	d, env := openDir(t)

	if err := d.SaveConfig(Config{Repos: []string{"/a", "/b"}}); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}
	cfg, err := LoadConfig(env)

	if err != nil || !slices.Equal(cfg.Repos, []string{"/a", "/b"}) || cfg.Version != 1 {
		t.Errorf("LoadConfig() = %+v, %v; want version 1 with both repos", cfg, err)
	}
}

func TestBrokenConfigIsAnErrorWithoutContent(t *testing.T) {
	d, env := openDir(t)
	const secret = "hunter2-plain-secret-no-pattern"
	if err := d.WriteFile(configFile, []byte(`{"repos": ["`+secret+`"`)); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(env)

	if !errors.Is(err, ErrBadConfig) {
		t.Fatalf("LoadConfig() error = %v, want ErrBadConfig", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error = %q, leaks the file's content", err)
	}
	if !strings.Contains(err.Error(), filepath.Join(env.StateDir, configFile)) {
		t.Errorf("error = %q, want it to name the file", err)
	}
}

func TestNewerConfigVersionIsRefused(t *testing.T) {
	d, env := openDir(t)
	if err := d.WriteFile(configFile, []byte(`{"version": 99, "repos": []}`)); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadConfig(env); !errors.Is(err, ErrBadConfig) {
		t.Errorf("LoadConfig() error = %v, want ErrBadConfig for a version jarx doesn't know", err)
	}
}

func TestSaveThenLoadLLMSettings(t *testing.T) {
	d, env := openDir(t)
	want := LLM{BaseURL: "https://llm.example.com/v1", Model: "m-1", KeyEnv: "JARX_LLM_KEY"}

	if err := d.SaveConfig(Config{LLM: &want}); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}
	cfg, err := LoadConfig(env)

	if err != nil || cfg.LLM == nil || *cfg.LLM != want {
		t.Errorf("LoadConfig() = %+v, %v; want LLM %+v", cfg, err, want)
	}
}

func TestConfigWithoutLLMSettingsHasNoLLMKey(t *testing.T) {
	d, env := openDir(t)

	if err := d.SaveConfig(Config{}); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}
	data, err := os.ReadFile(filepath.Join(env.StateDir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "llm") {
		t.Errorf("config.json = %s, want no llm key when it's off", data)
	}
}
