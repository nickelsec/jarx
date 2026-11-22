package platform

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// jarxEnvName is the file in a fake home that stands in for the env.
const jarxEnvName = ".jarx-env"

// FromHome returns an Env rooted in the fake home dir. Env vars and PATH come
// only from <dir>/.jarx-env, jarx's state lives in <dir>/.jarx-state, and
// system roots are off. Nothing is read from the real env.
func FromHome(dir string) (Env, error) {
	home, err := filepath.Abs(dir)
	if err != nil {
		return Env{}, fmt.Errorf("home %s: %w", dir, err)
	}
	info, err := os.Stat(home)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Env{}, fmt.Errorf("home %s does not exist", home)
	case err != nil:
		return Env{}, fmt.Errorf("home %s: %w", home, err)
	case !info.IsDir():
		return Env{}, fmt.Errorf("home %s is not a directory", home)
	}

	environ, err := readJarxEnv(home)
	if err != nil {
		return Env{}, err
	}
	return newEnv(runtime.GOOS, home, filepath.Join(home, StateDirName), environ, false, true), nil
}

// readJarxEnv reads <home>/.jarx-env: KEY=VALUE lines, with blank lines and
// # comments skipped. Values are kept exactly as written. A missing file
// means an empty env. Errors name the line number only, never its content,
// since the file can hold fake secrets.
func readJarxEnv(home string) ([]string, error) {
	root, err := os.OpenRoot(home)
	if err != nil {
		return nil, fmt.Errorf("opening home %s: %w", home, err)
	}
	defer func() { _ = root.Close() }()

	data, err := root.ReadFile(jarxEnvName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", jarxEnvName, err)
	}

	var environ []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return nil, fmt.Errorf("%s line %d: want KEY=VALUE", jarxEnvName, n)
		}
		environ = append(environ, key+"="+value)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", jarxEnvName, err)
	}
	return environ, nil
}
