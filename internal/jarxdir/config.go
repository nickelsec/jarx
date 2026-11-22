package jarxdir

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/nickelsec/jarx/internal/platform"
)

const (
	configFile    = "config.json"
	configVersion = 1
)

// ErrBadConfig means jarx's own config file couldn't be used.
var ErrBadConfig = errors.New("bad config")

// Config is jarx's own settings. The LLM settings join it in phase 8.
type Config struct {
	Version int      `json:"version"`
	Repos   []string `json:"repos"` // extra project paths, absolute
}

// LoadConfig reads jarx's config. With nothing saved it returns an empty
// config, and it never creates the state dir: a scan that saves nothing
// writes nothing.
func LoadConfig(env platform.Env) (Config, error) {
	path := filepath.Join(env.StateDir, configFile)
	root, err := os.OpenRoot(env.StateDir)
	if errors.Is(err, fs.ErrNotExist) {
		return Config{Version: configVersion}, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("opening state dir: %w", err)
	}
	defer func() { _ = root.Close() }()

	data, err := root.ReadFile(configFile)
	if errors.Is(err, fs.ErrNotExist) {
		return Config{Version: configVersion}, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("reading %s: %w", path, err)
	}
	var cfg Config
	// The JSON error isn't included: it can quote what's in the file.
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("%w: %s isn't valid JSON; fix it or delete it", ErrBadConfig, path)
	}
	if cfg.Version > configVersion {
		return Config{}, fmt.Errorf("%w: %s is version %d, from a newer jarx", ErrBadConfig, path, cfg.Version)
	}
	cfg.Version = configVersion
	return cfg, nil
}

// SaveConfig writes jarx's config.
func (d *Dir) SaveConfig(cfg Config) error {
	cfg.Version = configVersion
	if cfg.Repos == nil {
		cfg.Repos = []string{}
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}
	return d.WriteFile(configFile, append(data, '\n'))
}
