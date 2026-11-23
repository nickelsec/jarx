package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Real returns the Env for the machine jarx is running on. These are the
// only reads of the real env and user dirs in jarx; lint bans them
// everywhere else.
func Real() (Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Env{}, fmt.Errorf("finding the home dir: %w", err)
	}
	config, err := os.UserConfigDir()
	if err != nil {
		return Env{}, fmt.Errorf("finding the user config dir: %w", err)
	}
	env := newEnv(runtime.GOOS, home, filepath.Join(config, "jarx"), os.Environ(), true, false)
	env.registry = realRegistry()
	return env, nil
}

// LookupReal reads one variable from the real env, for a process that runs
// without a home dir, like the demo's fake MCP server checking its marker.
func LookupReal(name string) (string, bool) { return os.LookupEnv(name) }
