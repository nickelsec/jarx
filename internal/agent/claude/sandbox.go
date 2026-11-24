package claude

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/nickelsec/jarx/internal/catalog"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// Settings that shape permissions without being rules: the sandbox switches
// and enableAllProjectMcpServers. Sandbox paths become rules.
const (
	keySandboxOn       = "sandbox.enabled"
	keyAutoAllowBash   = "sandbox.autoAllowBashIfSandboxed"
	keyUnsandboxed     = "sandbox.allowUnsandboxedCommands"
	keyAllProjectMCP   = "enableAllProjectMcpServers"
	sandboxPathsPrefix = "sandbox.filesystem."
	goosWindows        = "windows"
)

// sandboxPaths maps each sandbox.filesystem list to the rule action it is.
//
//nolint:gochecknoglobals // fixed list, read only
var sandboxPaths = []struct {
	key    string
	action model.RuleAction
}{
	{"denyRead", model.RuleDeny},
	{"denyWrite", model.RuleDeny},
	{"allowRead", model.RuleRead},
	{"allowWrite", model.RuleWrite},
}

// option is one setting a layer sets, kept as its JSON text.
type option struct {
	key   string
	value redact.Text
	raw   string
}

// optionValue reads a scalar setting. Anything that isn't a bool or a
// string is skipped with a finding.
func (r *layerReader) optionValue(key string, raw json.RawMessage) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		r.problem(key + " isn't valid JSON, skipped")
		return
	}
	var s string
	switch x := v.(type) {
	case bool:
		s = "false"
		if x {
			s = "true"
		}
	case string:
		s = x
	case float64:
		s = strconv.FormatFloat(x, 'f', -1, 64)
	default:
		r.problem(key + " isn't a bool, a number or a string, skipped")
		return
	}
	r.l.options = append(r.l.options, option{key: key, value: r.scrub(s), raw: s})
}

// sandbox reads the sandbox keys jarx shows in the permissions view.
func (r *layerReader) sandbox(raw json.RawMessage) {
	var sb map[string]json.RawMessage
	if err := json.Unmarshal(raw, &sb); err != nil {
		r.problem("sandbox isn't a JSON object")
		return
	}
	for _, key := range []string{"enabled", "autoAllowBashIfSandboxed", "allowUnsandboxedCommands"} {
		if v, ok := sb[key]; ok && r.readable("sandbox."+key) {
			r.optionValue("sandbox."+key, v)
		}
	}
	for key, read := range map[string]func(json.RawMessage){
		"filesystem": r.sandboxFilesystem, "excludedCommands": r.excludedCommands,
		"credentials": r.sandboxCredentials, "network": r.sandboxNetwork,
	} {
		if v, ok := sb[key]; ok {
			read(v)
		}
	}
}

// excludedCommands reads the command patterns Claude runs outside the
// sandbox.
func (r *layerReader) excludedCommands(raw json.RawMessage) {
	if !r.readable("sandbox.excludedCommands") {
		return
	}
	for _, cmd := range r.strings("sandbox.excludedCommands", raw) {
		r.l.rules = append(r.l.rules, model.PermissionRule{
			Action: model.RuleExclude, Rule: r.scrub("sandbox.excludedCommands " + cmd.String()), Target: cmd, Origin: r.l.origin,
		})
	}
}

// maskUserInfo masks a password in a URL value, like a proxy's
// http://user:pass@host, before it's kept. It doesn't rely on the secret
// patterns catching it.
func (r *layerReader) maskUserInfo(raw json.RawMessage) json.RawMessage {
	var v string
	if json.Unmarshal(raw, &v) != nil {
		return raw
	}
	u, err := url.Parse(v)
	if err != nil || u.User == nil {
		return raw
	}
	pw, ok := u.User.Password()
	if !ok || pw == "" {
		return raw
	}
	masked, _ := r.c.Scrub.Secret("url_password", pw)
	out, err := json.Marshal(strings.Replace(v, ":"+pw+"@", ":"+masked.String()+"@", 1))
	if err != nil {
		return raw
	}
	return out
}

// sandboxNetwork reads the sandbox's domain lists as rules and its proxy
// ports as options, for where Claude talks to.
func (r *layerReader) sandboxNetwork(raw json.RawMessage) {
	var nw map[string]json.RawMessage
	if json.Unmarshal(raw, &nw) != nil {
		r.problem("sandbox.network isn't a JSON object")
		return
	}
	for list, action := range map[string]model.RuleAction{"allowedDomains": model.RuleAllow, "deniedDomains": model.RuleDeny} {
		key := "sandbox.network." + list
		v, ok := nw[list]
		if !ok || !r.readable(key) {
			continue
		}
		for _, d := range r.strings(key, v) {
			r.l.rules = append(r.l.rules, model.PermissionRule{
				Action: action, Rule: r.scrub(key + " " + d.String()), Target: d, Origin: r.l.origin,
			})
		}
	}
	for _, port := range []string{"httpProxyPort", "socksProxyPort"} {
		if v, ok := nw[port]; ok && r.readable("sandbox.network."+port) {
			r.optionValue("sandbox.network."+port, v)
		}
	}
}

// credentialEntry is one sandbox.credentials entry: a file path or an env
// var name, and its mode.
type credentialEntry struct {
	Path string `json:"path"`
	Name string `json:"name"`
	Mode string `json:"mode"`
}

// sandboxCredentials reads sandbox.credentials.files and envVars as rules.
func (r *layerReader) sandboxCredentials(raw json.RawMessage) {
	var cr map[string]json.RawMessage
	if json.Unmarshal(raw, &cr) != nil {
		r.problem("sandbox.credentials isn't a JSON object")
		return
	}
	for _, list := range []string{credFiles, credEnvVars} {
		key := "sandbox.credentials." + list
		v, ok := cr[list]
		if !ok || !r.readable(key) {
			continue
		}
		var entries []credentialEntry
		if json.Unmarshal(v, &entries) != nil {
			r.problem(key + " isn't a list of entries, skipped")
			continue
		}
		for _, e := range entries {
			r.credentialRule(key, list, e)
		}
	}
}

// The two lists in sandbox.credentials.
const (
	credFiles   = "files"
	credEnvVars = "envVars"
)

// credentialRule adds one sandbox.credentials entry as a rule: deny blocks
// sandboxed commands, mask hands them a stand-in.
func (r *layerReader) credentialRule(key, list string, e credentialEntry) {
	target, what := e.Path, "path"
	if list == credEnvVars {
		target, what = e.Name, "name"
	}
	action := model.RuleDeny
	if e.Mode == "mask" {
		action = model.RuleMask
	}
	if target == "" || (e.Mode != "deny" && e.Mode != "mask") {
		r.problem(key + " has an entry with no " + what + " or an unknown mode, skipped")
		return
	}
	r.l.rules = append(r.l.rules, model.PermissionRule{
		Action: action, Rule: r.scrub(key + " " + target), Target: r.scrub(target), Origin: r.l.origin,
	})
}

// envNames keeps the names in a settings file's env block, in file order.
// The values never leave this function.
func (r *layerReader) envNames(raw json.RawMessage) {
	d := json.NewDecoder(bytes.NewReader(raw))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		r.problem("env isn't a JSON object")
		return
	}
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return
		}
		name, _ := t.(string)
		var skip json.RawMessage
		if d.Decode(&skip) != nil {
			return
		}
		if _, ok := catalog.EgressVarArea(name); ok {
			r.optionValue("env."+name, r.maskUserInfo(skip)) // a URL, path or switch, never a secret
		}
		clear(skip)
		r.l.env = append(r.l.env, r.scrub(name))
	}
}

// sandboxFilesystem reads the sandbox's path lists as rules.
func (r *layerReader) sandboxFilesystem(raw json.RawMessage) {
	var fsys map[string]json.RawMessage
	if json.Unmarshal(raw, &fsys) != nil {
		return
	}
	if v, ok := fsys["disabled"]; ok && r.readable(sandboxPathsPrefix+"disabled") {
		r.optionValue(sandboxPathsPrefix+"disabled", v)
	}
	for _, p := range sandboxPaths {
		full := sandboxPathsPrefix + p.key
		v, ok := fsys[p.key]
		if !ok || !r.readable(full) {
			continue
		}
		for _, path := range r.strings(full, v) {
			r.l.rules = append(r.l.rules, model.PermissionRule{
				Action: p.action, Rule: r.scrub(full + " " + path.String()), Target: path, Origin: r.l.origin,
			})
		}
	}
}

// readable reports whether this file may set key.
func (r *layerReader) readable(key string) bool {
	_, allowed := keyAllowed(key, r.l.origin.Scope)
	return allowed
}

// addOption shows a setting in the view. Values from a repo file of a
// folder that isn't trusted wait for trust, like project allow rules.
func (m *merger) addOption(l *layer, opt option) {
	o := l.origin
	if o.InEffect && m.waits != "" && (o.Scope == model.ScopeProject || (o.Scope == model.ScopeLocal && !m.home)) {
		o.InEffect, o.Why = false, m.why(string(o.Scope)+" setting "+m.waits)
	}
	m.optionLayer(opt.key, model.Layer[redact.Text]{Value: opt.value, Origin: o})
}

// optionLayer adds one layer to the option named key, making it if needed.
func (m *merger) optionLayer(key string, layer model.Layer[redact.Text]) {
	for i := range m.perm.Options {
		if m.perm.Options[i].Key.String() == key {
			m.perm.Options[i].Setting.Layers = append(m.perm.Options[i].Setting.Layers, layer)
			return
		}
	}
	m.perm.Options = append(m.perm.Options, model.Option{
		Key: m.why(key), Setting: model.Setting[redact.Text]{Layers: []model.Layer[redact.Text]{layer}},
	})
}

// settleSandbox leaves sandbox paths and switches in effect only when the
// sandbox runs: sandbox.enabled is true in the highest file that sets it,
// and the OS isn't native Windows (the docs list macOS, Linux and WSL2).
func (m *merger) settleSandbox() {
	why := m.sandboxOff()
	if why == "" {
		return
	}
	off := func(o *model.Origin) {
		if o.InEffect {
			o.InEffect, o.Why = false, m.why(why)
		}
	}
	for i := range m.perm.Rules {
		if strings.HasPrefix(m.perm.Rules[i].Rule.String(), "sandbox.") {
			off(&m.perm.Rules[i].Origin) // paths, credential entries and excluded commands
		}
	}
	m.sandboxOptionsOff(off)
}

// sandboxOff says why the sandbox doesn't run here, or "" when it does.
func (m *merger) sandboxOff() string {
	if m.c.Env.GOOS == goosWindows {
		return "Claude's sandbox doesn't run on native Windows"
	}
	switch on, file := m.effective(keySandboxOn); {
	case file == "":
		return "the sandbox is off: no file sets sandbox.enabled to true"
	case on != "true":
		return "the sandbox is off: sandbox.enabled is " + on + " in " + file
	}
	return ""
}

// sandboxOptionsOff turns off the switches that only matter while the
// sandbox runs.
func (m *merger) sandboxOptionsOff(off func(*model.Origin)) {
	for i := range m.perm.Options {
		if k := m.perm.Options[i].Key.String(); k == keyAutoAllowBash || k == keyUnsandboxed {
			for j := range m.perm.Options[i].Setting.Layers {
				off(&m.perm.Options[i].Setting.Layers[j].Origin)
			}
		}
	}
}

// effective is the value of key from the highest layer in effect, and that
// layer's file, or "" when none sets it.
func (m *merger) effective(key string) (string, string) {
	for _, o := range m.perm.Options {
		if o.Key.String() != key {
			continue
		}
		if eff, ok := o.Setting.Effective(); ok {
			return eff.Value.String(), eff.Origin.File.Text().String()
		}
	}
	return "", ""
}
