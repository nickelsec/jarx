package credmeta

import (
	"io"
	"net/url"
	"slices"
	"strings"
)

// iniSection is one [section] of an ini file: its name and its key names.
// Values are never kept, except the ones a caller asks for by key.
type iniSection struct {
	name string
	keys []string
	kept map[string]string
}

// readINI reads the section names and key names of an ini file, keeping
// the values of the keys in keep only. Comments start with ; or #.
func readINI(r io.Reader, keep ...string) ([]iniSection, error) {
	var out []iniSection
	err := lines(r, func(line string) {
		t := strings.TrimSpace(line)
		switch {
		case t == "" || t[0] == ';' || t[0] == '#':
		case t[0] == '[' && t[len(t)-1] == ']':
			out = append(out, iniSection{name: strings.TrimSpace(t[1 : len(t)-1]), kept: map[string]string{}})
		case len(out) > 0:
			k, v, ok := strings.Cut(t, "=")
			if !ok {
				return // a continuation line of a list, like index-servers
			}
			k = strings.ToLower(strings.TrimSpace(k))
			s := &out[len(out)-1]
			s.keys = append(s.keys, k)
			if slices.Contains(keep, k) {
				s.kept[k] = strings.TrimSpace(v)
			}
		}
	})
	return out, err
}

// awsKinds names what kind of credential a profile has, from its key names.
//
//nolint:gochecknoglobals // fixed table, read only
var awsKinds = []struct{ label, keys string }{
	{"static keys", "aws_access_key_id aws_secret_access_key"},
	{"sso", "sso_session sso_start_url sso_account_id"},
	{"credential process", "credential_process"},
	{"role", "role_arn"},
	{"web identity", "web_identity_token_file"},
}

// parseAWS keeps profile names and the kind of credential each has. The
// config file names profiles [profile x], [default] and [sso-session x];
// the credentials file names them [x].
func parseAWS(_ string, r io.Reader) ([]Fact, error) {
	sections, err := readINI(r)
	out := make([]Fact, 0, len(sections))
	for _, s := range sections {
		label := "profile " + strings.TrimSpace(strings.TrimPrefix(s.name, "profile "))
		session := false
		if n, ok := strings.CutPrefix(s.name, "sso-session "); ok {
			label, session = "sso session "+strings.TrimSpace(n), true
		}
		if !name.MatchString(strings.TrimPrefix(strings.TrimPrefix(label, "profile "), "sso session ")) {
			continue
		}
		var kinds []string // a session isn't a profile, so it has no kind
		for _, k := range awsKinds {
			if session {
				break
			}
			if slices.ContainsFunc(strings.Fields(k.keys), func(key string) bool { return slices.Contains(s.keys, key) }) {
				kinds = append(kinds, k.label)
			}
		}
		out = append(out, Fact{label, strings.Join(kinds, ", ")})
	}
	return out, err
}

// parsePypirc keeps index server names and the host of each repository
// URL, never a username or password.
func parsePypirc(_ string, r io.Reader) ([]Fact, error) {
	sections, err := readINI(r, "repository")
	out := make([]Fact, 0, len(sections))
	for _, s := range sections {
		if s.name == "distutils" || !name.MatchString(s.name) {
			continue
		}
		out = append(out, Fact{"index server " + s.name, urlHost(s.kept["repository"])})
	}
	return out, err
}

// urlHost is the host (and port) of a URL, without any user info, or "".
func urlHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || !name.MatchString(u.Host) {
		return ""
	}
	return u.Host
}

// npmAuthKeys are the npmrc keys that hold a registry credential.
//
//nolint:gochecknoglobals // fixed list, read only
var npmAuthKeys = []string{"_authToken", "_auth", "_password"}

// parseNpmrc keeps the registries that have an auth key and the key's
// name. A key scoped to a registry looks like //host/path/:_authToken.
func parseNpmrc(_ string, r io.Reader) ([]Fact, error) {
	var out []Fact
	err := lines(r, func(line string) {
		t := strings.TrimSpace(line)
		if t == "" || t[0] == ';' || t[0] == '#' {
			return
		}
		k, _, ok := strings.Cut(t, "=")
		if !ok {
			return
		}
		k = strings.TrimSpace(k)
		scope, key := "", k
		if i := strings.LastIndex(k, ":"); strings.HasPrefix(k, "//") && i > 0 {
			scope, key = k[2:i], k[i+1:]
		}
		if !slices.Contains(npmAuthKeys, key) {
			return
		}
		switch {
		case scope == "":
			out = append(out, Fact{"default registry", key})
		case name.MatchString(scope):
			out = append(out, Fact{"registry " + scope, key})
		}
	})
	return out, err
}
