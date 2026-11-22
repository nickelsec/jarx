package codex

import (
	"errors"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
)

// Codex config layers, from developers.openai.com/codex/config-file
// (config-basic and config-advanced), /permissions and
// /enterprise/managed-configuration, highest first:
//
//   - legacy managed_config.toml, which at startup sits above the user's
//     config and even CLI --config flags
//   - CLI flags (not visible to jarx)
//   - project .codex/config.toml files from the project root marker down to
//     the working dir, closest first, trusted projects only
//   - a profile file ~/.codex/<name>.config.toml, only with --profile
//   - the user's ~/.codex/config.toml
//   - cloud-managed defaults (not visible to jarx)
//   - /etc/codex/config.toml on Unix
//
// requirements.toml constrains values rather than setting them: a value it
// doesn't allow falls back to an allowed one. If sandbox_mode is set in any
// loaded layer, Codex uses the legacy sandbox and ignores
// default_permissions, unless managed allowed_permission_profiles is set.

// optionKeys are the settings jarx records, in report order.
//
//nolint:gochecknoglobals // fixed list, read only
var optionKeys = []string{
	"approval_policy", "approvals_reviewer", keySandboxMode, keyDefaultPerm, keyWebSearch,
	"sandbox_workspace_write.network_access",
	"shell_environment_policy.inherit", "shell_environment_policy.ignore_default_excludes",
}

const (
	keySandboxMode = "sandbox_mode"
	keyDefaultPerm = "default_permissions"
	keyWebSearch   = "web_search"
	goosWindows    = "windows"
)

// RepoDropsPermissions is the finding for a project config whose
// sandbox_mode makes Codex ignore the default_permissions another layer
// sets, which turns off every rule in that profile, deny rules included.
func RepoDropsPermissions() finding.Rule {
	return finding.Rule{
		ID:       "JARX-CODEX-001",
		Severity: finding.High,
		Title:    "a repository's sandbox_mode turns off your permission profile",
		Fix:      "remove sandbox_mode from the project's .codex/config.toml, or untrust the project",
	}
}

// RepoWidensProfile is the finding for a project config that changes a
// permission profile another layer defines.
func RepoWidensProfile() finding.Rule {
	return finding.Rule{
		ID:       "JARX-CODEX-002",
		Severity: finding.Medium,
		Title:    "a repository changes one of your permission profiles",
		Fix:      "check what the project's [permissions] entries add or replace",
	}
}

// LegacyManagedConfig is the finding for a legacy managed_config.toml, which
// overrides the user's config and CLI flags at startup.
func LegacyManagedConfig() finding.Rule {
	return finding.Rule{
		ID:       "JARX-CODEX-003",
		Severity: finding.Info,
		Title:    "a legacy managed_config.toml overrides your config and CLI flags at startup",
		Fix:      "settings in this file win over config.toml and --config each time Codex starts",
	}
}

// LegacyProfiles is the finding for [profiles] tables or a profile key in a
// config file, which Codex 0.134.0 and later ignore.
func LegacyProfiles() finding.Rule {
	return finding.Rule{
		ID:       "JARX-CODEX-004",
		Severity: finding.Info,
		Title:    "legacy profiles in config.toml are ignored",
		Fix:      "move each [profiles.<name>] table to ~/.codex/<name>.config.toml and use --profile <name>",
	}
}

// OwnSandboxModeWins is the finding for sandbox_mode and default_permissions
// both set in the user's own layers, so the permission profile is ignored.
func OwnSandboxModeWins() finding.Rule {
	return finding.Rule{
		ID:       "JARX-CODEX-005",
		Severity: finding.Medium,
		Title:    "sandbox_mode makes Codex ignore your permission profile",
		Fix:      "set either sandbox_mode or default_permissions, not both",
	}
}

// Rules returns the rules the Codex adapter owns.
func Rules() []finding.Rule {
	return []finding.Rule{RepoDropsPermissions(), RepoWidensProfile(), LegacyManagedConfig(), LegacyProfiles(), OwnSandboxModeWins(), RepoChangesInstructions()}
}

// systemConfigFor, requirementsFor and managedConfigFor are the documented
// system paths. Windows has no system config.toml.
func systemConfigFor(goos string, r platform.Roots) string {
	if goos == goosWindows || r.Etc == "" {
		return ""
	}
	return filepath.Join(r.Etc, "codex", "config.toml")
}

func requirementsFor(goos string, r platform.Roots) string {
	if goos == goosWindows {
		if r.ProgramData == "" {
			return ""
		}
		return filepath.Join(r.ProgramData, "OpenAI", "Codex", "requirements.toml")
	}
	if r.Etc == "" {
		return ""
	}
	return filepath.Join(r.Etc, "codex", "requirements.toml")
}

func managedConfigFor(goos string, r platform.Roots, home string) string {
	if goos == goosWindows {
		return filepath.Join(home, "managed_config.toml")
	}
	if r.Etc == "" {
		return ""
	}
	return filepath.Join(r.Etc, "codex", "managed_config.toml")
}

func codexHome(env platform.Env) string {
	if dir, ok := env.Lookup("CODEX_HOME"); ok && dir != "" {
		return env.MapPath(dir)
	}
	return filepath.Join(env.Home, ".codex")
}

func systemConfigFile(env platform.Env) string {
	roots, ok := env.SystemRoots()
	if !ok {
		return ""
	}
	return systemConfigFor(env.GOOS, roots)
}

func requirementsFile(env platform.Env) string {
	roots, ok := env.SystemRoots()
	if !ok {
		return ""
	}
	return requirementsFor(env.GOOS, roots)
}

func managedConfigFile(env platform.Env) string {
	roots, _ := env.SystemRoots()
	return managedConfigFor(env.GOOS, roots, codexHome(env))
}

// layer is what jarx keeps from one config file.
type layer struct {
	origin   model.Origin
	values   map[string]string            // option key to value, raw
	profiles map[string]map[string]string // profile name to path to access, raw
	markers  []string                     // project_root_markers
	hasMarks bool                         // project_root_markers is set, maybe to []
	legacy   bool                         // has [profiles] or a profile key
	raw      map[string]any               // the decoded file
	_        struct{}
}

// requirements is what jarx reads from requirements.toml.
type requirements struct {
	origin   model.Origin
	allowed  map[string][]string // option key to allowed values
	profiles map[string]bool     // allowed_permission_profiles
	raw      map[string]any      // the decoded file, for hooks and features
}

// The adapter reads settings.
var _ agent.SettingsReader = Adapter{}

// Settings reads each ok project's Codex config layers and stores the
// merged result on it.
func (Adapter) Settings(c agent.Context, projects []model.Project) ([]model.Unknown, []finding.Finding) {
	s := &settings{c: c}
	s.load()
	var perProject []finding.Finding
	for i := range projects {
		p := &projects[i]
		if p.Status != model.ProjectOK {
			continue
		}
		v := s.forProject(*p)
		if perm, ok := v.permissions(); ok {
			p.Permissions = append(p.Permissions, perm)
		}
		perProject = append(perProject, v.findings...)
	}
	// Reading project files can add to s.findings, so take them last.
	return nil, append(s.findings, perProject...)
}

// settings holds the layers every project shares.
type settings struct {
	c                     agent.Context
	managed, user, system *layer
	profiles              []*layer
	req                   *requirements
	findings              []finding.Finding
}

func (s *settings) text(v string) redact.Text {
	t, _ := s.c.Scrub.Scrub(v)
	return t
}

func (s *settings) load() {
	home := codexHome(s.c.Env)
	s.managed = s.read(managedConfigFile(s.c.Env), model.ScopeManaged)
	s.user = s.read(filepath.Join(home, "config.toml"), model.ScopeUser)
	s.system = s.read(systemConfigFile(s.c.Env), model.ScopeSystem)
	s.profiles = s.profileFiles(home)
	s.req = s.readRequirements(requirementsFile(s.c.Env))
	if s.managed != nil && len(s.managed.raw) > 0 {
		ev := s.text("managed_config.toml sets " + strings.Join(sortedKeys(s.managed.raw), ", "))
		s.findings = append(s.findings, LegacyManagedConfig().New(s.managed.origin, ev))
	}
	for _, l := range []*layer{s.managed, s.user, s.system} {
		if l != nil && l.legacy {
			s.findings = append(s.findings, LegacyProfiles().New(l.origin, s.text("the file has [profiles] tables or a profile key")))
		}
	}
}

// profileFiles lists ~/.codex/<name>.config.toml. They apply only with
// --profile <name>, which jarx can't see.
func (s *settings) profileFiles(home string) []*layer {
	entries, err := s.c.Files.ReadDir(home)
	if err != nil {
		return nil
	}
	var out []*layer
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".config.toml")
		if !ok || name == "" || !e.Type().IsRegular() {
			continue
		}
		if l := s.read(filepath.Join(home, e.Name()), model.ScopeProfile); l != nil {
			l.origin.InEffect, l.origin.Why = false, s.text("applies only with --profile "+name)
			out = append(out, l)
		}
	}
	return out
}

// read reads one config file. A missing file is nil. A broken one is a
// finding with the line, never the content.
func (s *settings) read(path string, scope model.Scope) *layer {
	if path == "" {
		return nil
	}
	origin := model.Origin{Agent: model.AgentCodex, File: model.NewPath(s.c.Scrub, path), Scope: scope, InEffect: true}
	data, err := s.c.Files.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, fsys.ErrTooLarge):
		return nil // too large is recorded by fsys and reported by discover
	case err != nil:
		s.problem(origin, "couldn't read the file")
		return nil
	}
	var raw map[string]any
	if _, err := toml.Decode(string(data), &raw); err != nil {
		if perr, ok := errors.AsType[toml.ParseError](err); ok {
			origin.Line = perr.Position.Line
		}
		s.problem(origin, "not valid TOML")
		return nil
	}
	return parseLayer(origin, raw)
}

func (s *settings) problem(origin model.Origin, why string) {
	s.findings = append(s.findings, finding.UnreadableRecord().New(origin, s.text(why)))
}

// parseLayer picks the settings jarx records out of a decoded file.
func parseLayer(origin model.Origin, raw map[string]any) *layer {
	l := &layer{origin: origin, values: map[string]string{}, profiles: map[string]map[string]string{}, raw: raw}
	for _, key := range optionKeys {
		if v, ok := lookup(raw, key); ok {
			l.values[key] = scalar(v)
		}
	}
	_, hasProfiles := raw["profiles"]
	_, hasProfile := raw["profile"]
	l.legacy = hasProfiles || hasProfile
	if m, ok := raw["project_root_markers"].([]any); ok {
		l.hasMarks = true
		for _, v := range m {
			if s, ok := v.(string); ok {
				l.markers = append(l.markers, s)
			}
		}
	}
	perms, _ := raw["permissions"].(map[string]any)
	for name, v := range perms {
		profile, _ := v.(map[string]any)
		fsTable, _ := profile["filesystem"].(map[string]any)
		rules := map[string]string{}
		flattenRules(fsTable, "", rules)
		l.profiles[name] = rules
	}
	return l
}

// flattenRules turns a filesystem table into path to access, with nested
// tables like ":workspace_roots" as a prefix.
func flattenRules(t map[string]any, prefix string, out map[string]string) {
	for k, v := range t {
		switch v := v.(type) {
		case string:
			out[prefix+k] = v
		case map[string]any:
			flattenRules(v, prefix+k+"/", out)
		}
	}
}

// lookup finds a dotted key in a decoded TOML table.
func lookup(raw map[string]any, key string) (any, bool) {
	cur := any(raw)
	for part := range strings.SplitSeq(key, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// scalar renders a TOML value as text. A table (like a granular approval
// policy) becomes its kind.
func scalar(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case map[string]any:
		if len(v) == 1 {
			for k := range v {
				return k
			}
		}
		return "table"
	default:
		return "value"
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// readRequirements reads requirements.toml.
func (s *settings) readRequirements(path string) *requirements {
	l := s.read(path, model.ScopeRequirements)
	if l == nil {
		return nil
	}
	r := &requirements{origin: l.origin, allowed: map[string][]string{}, raw: l.raw}
	for key, req := range map[string]string{
		"approval_policy": "allowed_approval_policies", keySandboxMode: "allowed_sandbox_modes", keyWebSearch: "allowed_web_search_modes",
	} {
		list, ok := l.raw[req].([]any)
		if !ok {
			continue
		}
		vals := []string{}
		for _, v := range list {
			if str, ok := v.(string); ok {
				vals = append(vals, str)
			}
		}
		if key == keyWebSearch {
			vals = append(vals, "disabled") // always allowed, per the docs
		}
		r.allowed[key] = vals
	}
	if t, ok := l.raw["allowed_permission_profiles"].(map[string]any); ok {
		r.profiles = map[string]bool{}
		for name, v := range t {
			on, _ := v.(bool)
			r.profiles[name] = on
		}
	}
	return r
}
