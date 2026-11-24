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

// JarxEnvName is the file in a fake home that stands in for the env.
const JarxEnvName = ".jarx-env"

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
	env := newEnv(runtime.GOOS, home, filepath.Join(home, StateDirName), environ, false, true)
	if raw, ok := env.Lookup("PATH"); ok {
		env.Path = fakePath(env.GOOS, home, raw)
	}
	return env, nil
}

// fakePath splits a fake home's PATH. One demo .jarx-env serves every OS,
// so ; separates entries everywhere (it can't be part of a Windows path),
// as well as the OS's own separator. A fake home moves around (the demo is
// copied before a scan), so each entry may start from the home with ~.
func fakePath(goos, home, raw string) []string {
	var out []string
	for part := range strings.SplitSeq(raw, ";") {
		for _, dir := range splitPath(goos, part) {
			out = append(out, fromHome(home, dir))
		}
	}
	return out
}

// envValue is a .jarx-env value with a leading ~ expanded. PATH is a list,
// so FromHome expands each of its entries instead.
func envValue(home, key, value string) string {
	if strings.EqualFold(key, "PATH") {
		return value
	}
	return fromHome(home, value)
}

// fromHome expands a leading ~ or ~/ to the fake home. A ~ anywhere else
// stays as written.
func fromHome(home, v string) string {
	if v == "~" {
		return home
	}
	if rest, ok := strings.CutPrefix(v, "~/"); ok {
		return filepath.Join(home, filepath.FromSlash(rest))
	}
	return v
}

// readJarxEnv reads <home>/.jarx-env: KEY=VALUE lines, with blank lines and
// # comments skipped. Values are kept as written, except that a leading ~
// or ~/ is the fake home, like a shell assignment. A missing file
// means an empty env. Errors name the line number only, never its content,
// since the file can hold fake secrets.
func readJarxEnv(home string) ([]string, error) {
	root, err := os.OpenRoot(home)
	if err != nil {
		return nil, fmt.Errorf("opening home %s: %w", home, err)
	}
	defer func() { _ = root.Close() }()

	data, err := root.ReadFile(JarxEnvName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", JarxEnvName, err)
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
			return nil, fmt.Errorf("%s line %d: want KEY=VALUE", JarxEnvName, n)
		}
		environ = append(environ, key+"="+envValue(home, key, value))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", JarxEnvName, err)
	}
	return environ, nil
}
