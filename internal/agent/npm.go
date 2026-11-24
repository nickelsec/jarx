package agent

import (
	"encoding/json"
	"path/filepath"
	"slices"

	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// NPMInstalls finds a global npm install of pkg, an agent's package. Paths
// follow npm's folders doc (docs.npmjs.com/cli/configuring-npm/folders):
// the prefix is the npm_config_prefix env var when set, else %AppData%\npm
// on Windows and /usr/local elsewhere. Packages live in
// {prefix}/lib/node_modules on Unix and {prefix}/node_modules on Windows,
// and commands in {prefix}/bin on Unix and {prefix} itself on Windows.
//
// A prefix set in .npmrc isn't seen: that file can hold auth tokens, so
// jarx never reads it.
func NPMInstalls(c Context, a model.Agent, pkg string) []model.Install {
	var out []model.Install
	for _, prefix := range npmPrefixes(c) {
		modules, bin := filepath.Join(prefix, "lib", "node_modules"), filepath.Join(prefix, "bin")
		if c.Env.GOOS == "windows" {
			modules, bin = filepath.Join(prefix, "node_modules"), prefix
		}
		dir := filepath.Join(modules, filepath.FromSlash(pkg))
		data, err := c.Files.ReadFile(filepath.Join(dir, "package.json"))
		if err != nil {
			continue
		}
		var meta struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		in := model.Install{Agent: a, Method: model.InstallNPM, Path: model.NewPath(c.Scrub, dir), BinDir: model.NewPath(c.Scrub, bin)}
		switch {
		case json.Unmarshal(data, &meta) != nil:
			in.VersionFrom = c.Text("package.json isn't valid JSON")
		case meta.Name != pkg:
			continue // some other package in that folder
		case meta.Version == "":
			in.VersionFrom = c.Text("package.json has no version")
		default:
			in.Version, in.VersionFrom = c.Text(meta.Version), c.Text("package.json")
		}
		out = append(out, in)
	}
	return out
}

// npmPrefixes are the global prefixes to look in, each once.
func npmPrefixes(c Context) []string {
	var out []string
	add := func(p string) {
		if p != "" && filepath.IsAbs(p) && !slices.Contains(out, filepath.Clean(p)) {
			out = append(out, filepath.Clean(p))
		}
	}
	// npm reads any npm_config_* env var as config, in any case.
	for _, name := range []string{"npm_config_prefix", "NPM_CONFIG_PREFIX"} {
		if v, ok := c.Env.Lookup(name); ok {
			add(v)
		}
	}
	if c.Env.GOOS == "windows" {
		if appData, ok := c.Env.Lookup("APPDATA"); ok {
			add(filepath.Join(appData, "npm"))
		}
	} else {
		add("/usr/local")
	}
	return out
}

// Text scrubs one of jarx's own strings or a value read from disk.
func (c Context) Text(s string) redact.Text {
	t, _ := c.Scrub.Scrub(s)
	return t
}
