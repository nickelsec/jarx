package catalog

import (
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/redact"
)

// body is n characters for a fake token body. Every token in this file is
// built at runtime, so nothing in the repo looks like a real one to a push
// scanner.
// It cycles 32 distinct chars, so it has real-token entropy.
func body(n int) string {
	const chars = "Xq7Lm2Pz9Rw4Tb8Nc1VdKj5Hs3Fg6Yu0"
	return strings.Repeat(chars, n/len(chars)+1)[:n]
}

func scrubber(t *testing.T) *redact.Scrubber {
	t.Helper()
	ps, err := Secrets()
	if err != nil {
		t.Fatalf("Secrets() error = %v", err)
	}
	s, err := redact.New(ps, nil)
	if err != nil {
		t.Fatalf("redact.New() error = %v", err)
	}
	return s
}

func kinds(s *redact.Scrubber, text string) []string {
	_, found := s.Scrub(text)
	out := make([]string, 0, len(found))
	for _, f := range found {
		out = append(out, f.Kind)
	}
	return out
}

func TestEachProviderFormatIsCaught(t *testing.T) {
	s := scrubber(t)
	for kind, sample := range map[string]string{
		"github_pat":          "ghp_" + body(36),
		"github_oauth":        "gho_" + body(36),
		"github_user_token":   "ghu_" + body(36),
		"github_app_token":    "ghs_" + body(36),
		"github_refresh":      "ghr_" + body(36),
		"github_fine_grained": "github_pat_" + body(22) + "_" + body(59),
		"gitlab_pat":          "glpat-" + body(20),
		"gitlab_token":        "gldt-" + body(20),
		"slack_token":         "xoxb-" + "1234567890-" + body(24),
		"slack_app_token":     "xapp-1-" + body(30),
		"stripe_secret":       "sk_" + "live_" + body(24),
		"stripe_restricted":   "rk_" + "live_" + body(24),
		"aws_access_key_id":   "AKIA" + strings.ToUpper(body(16)),
		"pypi_token":          "pypi-" + body(90),
		"digitalocean_token":  "dop_" + "v1_" + strings.Repeat("a1b2", 16),
		"anthropic_key":       "sk-ant-" + "api03-" + body(40),
		"google_api_key":      "AIza" + body(35),
		"sendgrid_key":        "SG." + body(22) + "." + body(43),
		"jwt":                 "eyJ" + body(20) + ".eyJ" + body(20) + "." + body(20),
		"private_key":         "-----BEGIN OPENSSH PRIVATE KEY-----\n" + body(40) + "\n-----END OPENSSH PRIVATE KEY-----",
	} {
		if got := kinds(s, "x "+sample+" y"); len(got) != 1 || got[0] != kind {
			t.Errorf("%s: kinds = %q, want [%s]", kind, got, kind)
		}
	}
}

func TestNearMissesAreLeftAlone(t *testing.T) {
	s := scrubber(t)
	for name, text := range map[string]string{
		"github prefix too short":      "ghp_" + body(10),
		"stripe publishable is public": "pk_" + "live_" + body(24),
		"aws id too short":             "AKIA" + strings.ToUpper(body(8)),
		"pypi too short":               "pypi-" + body(40),
		"a git sha":                    strings.Repeat("a1b2c3d4e5", 4),
		"a word with gh in it":         "ghostwriter_pattern",
	} {
		if got := kinds(s, text); len(got) != 0 {
			t.Errorf("%s: kinds = %q, want nothing", name, got)
		}
	}
}

func TestTheDemoValuesAreCaught(t *testing.T) {
	// The demo's fake values were made to not look like real tokens, so
	// GitHub's push protection lets them in. jarx still has to catch them,
	// by the name they're assigned to.
	s := scrubber(t)
	for _, line := range []string{
		"ANTHROPIC_API_KEY=sk-ant-demo-0000-not-a-real-key",
		"GITHUB_TOKEN=demo-not-a-real-token",
		"OPENAI_API_KEY=sk-demo-0000",
		`"DEPLOY_TOKEN": "demo-not-a-real-token"`,
		"db_password: hunter2-demo",
		"DB_PWD=hunter2-demo",
		"client_secret = 'demo-client-secret'",
		// No documented prefix for these, so the name is what catches them.
		"//registry.npmjs.org/:_authToken=npm_" + body(36),
		"HF_TOKEN=hf_" + body(34),
	} {
		got, found := s.Scrub(line)
		if len(found) == 0 || strings.Contains(got.String(), "demo-") || strings.Contains(got.String(), "hunter2") || strings.Contains(got.String(), body(30)) {
			t.Errorf("%q scrubbed to %q, want the value masked", line, got)
		}
	}
}

func TestNamedValuesThatArentSecretsAreLeftAlone(t *testing.T) {
	s := scrubber(t)
	for _, line := range []string{
		"max_tokens = 100000",
		`"apiKeyHelper": "/usr/local/bin/get-key.sh"`,
		"password_required: true",
		"token_path = ~/.cache/token",
		"API_KEY=${API_KEY}",
		"OPENAI_API_KEY=$OPENAI_API_KEY",
		`"secretName": "prod-db"`,
		"Bash(git *)",
		"use the --token flag",
		"PWD=/home/dev/project",
		"OLDPWD=/tmp",
		"credential_process = /usr/local/bin/creds",
		"credential_source = Ec2InstanceMetadata",
		`bearer_token_env_var = "DEPLOY_TOKEN"`,
		"model_auto_compact_token_limit = 200000",
	} {
		if got := kinds(s, line); len(got) != 0 {
			t.Errorf("%q: kinds = %q, want nothing", line, got)
		}
	}
}

func TestAKeyNameIsKeptAndOnlyTheValueMasked(t *testing.T) {
	s := scrubber(t)

	got, _ := s.Scrub("GITHUB_TOKEN=demo-not-a-real-token")

	if got.String() != "GITHUB_TOKEN=REDACTED:named_secret" {
		t.Errorf("Scrub() = %q, want the name kept", got)
	}
}

func TestAProviderKindWinsOverTheNameRule(t *testing.T) {
	s := scrubber(t)

	if got := kinds(s, "GITHUB_TOKEN=ghp_"+body(36)); len(got) != 1 || got[0] != "github_pat" {
		t.Errorf("kinds = %q, want github_pat: a known format beats the name rule", got)
	}
}

func TestCredentialsInURLsAndBearerHeadersAreMasked(t *testing.T) {
	s := scrubber(t)
	for line, want := range map[string]string{
		"https://deploy:" + body(16) + "@example.invalid/x": "https://deploy:REDACTED:url_password@example.invalid/x",
		"Authorization: Bearer " + body(32):                 "Authorization: Bearer REDACTED:bearer_token",
	} {
		if got, _ := s.Scrub(line); got.String() != want {
			t.Errorf("Scrub(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestTheTableHasADateAndASourcePerRow(t *testing.T) {
	rows, err := parseSecrets(secretsTSV)
	if err != nil {
		t.Fatalf("parseSecrets() error = %v", err)
	}
	if SecretsAsOf == "" {
		t.Error("SecretsAsOf is empty")
	}
	for _, r := range rows {
		if r.source == "" {
			t.Errorf("%s has no source", r.kind)
		}
	}
}

func TestBadRowsAreErrors(t *testing.T) {
	for name, tsv := range map[string]string{
		"bad regexp":   "x\tsrc\t([\n",
		"bad kind":     "Bad-Kind\tsrc\tabc\n",
		"missing cols": "x\tabc\n",
		"duplicate":    "x\tsrc\tabc\nx\tsrc\tdef\n",
	} {
		if _, err := parseSecrets(tsv); err == nil {
			t.Errorf("%s: parseSecrets() error = nil", name)
		}
	}
}

func placeholderFlag(t *testing.T, s *redact.Scrubber, line string) bool {
	t.Helper()
	_, found := s.Scrub(line)
	if len(found) != 1 {
		t.Fatalf("%q: found %d secrets, want 1", line, len(found))
	}
	return found[0].LikelyPlaceholder
}

func TestNamedPlaceholdersAreJudgedByShape(t *testing.T) {
	s := scrubber(t)
	for _, line := range []string{
		"API_KEY=your-api-key-here",
		"API_KEY=<your key>",
		"password: changeme",
		"DEPLOY_TOKEN=xxxxxxxxxxxx",
		"client_secret = EXAMPLE_SECRET",
		"DB_PASSWORD=placeholder",
		"DEPLOY_TOKEN=aaaaaaaa",
	} {
		if !placeholderFlag(t, s, line) {
			t.Errorf("%q: want LikelyPlaceholder", line)
		}
	}
	for _, line := range []string{
		"DB_PWD=hunter2", // short, so low entropy, but nothing says it's fake
		"GITHUB_TOKEN=demo-not-a-real-token",
		"API_KEY=" + body(32),
	} {
		if placeholderFlag(t, s, line) {
			t.Errorf("%q: want it treated as real", line)
		}
	}
}

func TestALongProviderTokenWithNoRandomnessIsAPlaceholder(t *testing.T) {
	s := scrubber(t)

	if !placeholderFlag(t, s, "ghp_"+strings.Repeat("a", 36)) {
		t.Error("want ghp_aaaa... flagged")
	}
	if placeholderFlag(t, s, "ghp_"+body(36)) {
		t.Error("want a varied token treated as real")
	}
}

func TestScrubbingTwiceChangesNothing(t *testing.T) {
	// A snapshot read back from disk goes through the scrubber again, so a
	// mask must never be masked a second time.
	ps, err := Secrets()
	if err != nil {
		t.Fatal(err)
	}
	s, err := redact.New(ps, staticKey("k"))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"GITHUB_TOKEN=demo-not-a-real-token",
		"Authorization: Bearer " + body(32),
		"curl -H 'x-api-key: " + body(24) + "' https://example.invalid",
		"https://deploy:" + body(16) + "@example.invalid/x",
	} {
		once, _ := s.Scrub(raw)
		twice, found := s.Scrub(once.String())
		if twice.String() != once.String() || len(found) != 0 {
			t.Errorf("%q: once %q, twice %q (%d new finds), want no change", raw, once, twice, len(found))
		}
	}
}

// staticKey is a fingerprint key for tests.
type staticKey []byte

func (k staticKey) Key() ([]byte, error) { return k, nil }

func TestALookAlikeMaskCantHideASecret(t *testing.T) {
	// Only a real mask (a kind the scrubber knows, then maybe a 12-hex
	// fingerprint, then a word boundary) is left alone, so text dressed up
	// as a mask can't hide the token that follows it.
	s := scrubber(t)
	token := "ghp_" + body(36)
	for _, raw := range []string{
		"REDACTED:" + token,
		"REDACTED:github_pat:" + token,
		"REDACTED:github_pat:" + strings.Repeat("a", 12) + ":" + token,
	} {
		if got, _ := s.Scrub(raw); strings.Contains(got.String(), token) {
			t.Errorf("Scrub(%q) = %q, want the token masked", raw, got)
		}
	}
	// Each guard on its own: a real kind with no boundary after it, and a
	// boundary after a word that isn't a kind.
	for raw, secret := range map[string]string{
		"https://deploy:REDACTED:github_pat" + body(16) + "@example.invalid/x": body(16),
		"API_KEY=REDACTED:hunter2value":                                        "hunter2value",
	} {
		if got, _ := s.Scrub(raw); strings.Contains(got.String(), secret) {
			t.Errorf("Scrub(%q) = %q, want %q masked", raw, got, secret)
		}
	}
}

func TestSecretNameUsesTheNameRule(t *testing.T) {
	for name, want := range map[string]bool{
		"GITHUB_TOKEN": true, "AWS_SECRET_ACCESS_KEY": true, "OPENAI_API_KEY": true, "DB_PASSWORD": true, "npm_token": true,
		"PATH": false, "EDITOR": false, "PWD": false, "OLDPWD": false, "apiKeyHelper": false, "TOKEN_PATH": false, "HOME": false,
	} {
		if got := SecretName(name); got != want {
			t.Errorf("SecretName(%s) = %v, want %v", name, got, want)
		}
	}
}
