// Package catalog holds jarx's embedded data, each part with an "as of" date.
package catalog

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"

	"github.com/nickelsec/jarx/internal/redact"
)

// SecretsAsOf is when the formats in secrets.tsv were last checked against
// the providers' docs.
const SecretsAsOf = "2026-11-22"

//go:embed secrets.tsv
var secretsTSV string

// minEntropy is the bits per char below which a match is flagged as a
// likely placeholder. It never decides whether to mask.
const minEntropy = 3.0

// tsvColumns is kind, source and regexp.
const tsvColumns = 3

// codeRules is how many patterns Secrets adds after the table.
const codeRules = 3

type secretRow struct {
	kind, source string
	re           *regexp.Regexp
}

var kindRe = regexp.MustCompile(`^[a-z0-9_]+$`)

func parseSecrets(tsv string) ([]secretRow, error) {
	var rows []secretRow
	seen := map[string]bool{}
	for n, line := range strings.Split(tsv, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) != tsvColumns {
			return nil, fmt.Errorf("secrets.tsv line %d: want kind, source and regexp, got %d columns", n+1, len(cols))
		}
		kind, source := cols[0], cols[1]
		if !kindRe.MatchString(kind) {
			return nil, fmt.Errorf("secrets.tsv line %d: bad kind %q", n+1, kind)
		}
		if seen[kind] {
			return nil, fmt.Errorf("secrets.tsv line %d: %s is listed twice", n+1, kind)
		}
		seen[kind] = true
		re, err := regexp.Compile(cols[2])
		if err != nil {
			return nil, fmt.Errorf("secrets.tsv line %d (%s): %w", n+1, kind, err)
		}
		rows = append(rows, secretRow{kind: kind, source: source, re: re})
	}
	return rows, nil
}

// Secrets returns every secret pattern: the documented formats first, then
// the rules for credentials in URLs and bearer headers, then the name rule.
// The order matters, since on a tie the earlier pattern names the kind.
func Secrets() ([]redact.Pattern, error) {
	rows, err := parseSecrets(secretsTSV)
	if err != nil {
		return nil, err
	}
	out := make([]redact.Pattern, 0, len(rows)+codeRules)
	for _, r := range rows {
		out = append(out, redact.Pattern{Kind: r.kind, Re: r.re, MinEntropy: minEntropy})
	}
	return append(out,
		redact.Pattern{Kind: "url_password", Re: urlPasswordRe, MinEntropy: minEntropy, Valid: notAReference},
		redact.Pattern{Kind: "bearer_token", Re: bearerRe, MinEntropy: minEntropy},
		redact.Pattern{Kind: "named_secret", Re: namedRe, Valid: namedValid, Placeholder: namedPlaceholder},
	), nil
}

// urlPasswordRe is the password in scheme://user:password@host (RFC 3986
// userinfo).
var urlPasswordRe = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.\-]*://[^\s:/@]+:(?P<secret>[^\s@/]+)@`)

// bearerRe is the token in an Authorization: Bearer header (RFC 6750).
var bearerRe = regexp.MustCompile(`(?i)\bbearer[ \t]+(?P<secret>[A-Za-z0-9\-._~+/]{16,}=*)`)

// namedRe is a value assigned to a name that says it's a secret, like
// GITHUB_TOKEN=..., "api_key": "..." or password: .... It catches values
// that have no documented format, like the demo's fakes.
var namedRe = regexp.MustCompile(`(?i)(?P<name>` + secretNamePart + `)["']?[ \t]*[:=][ \t]*["']?(?P<secret>[^\s"'` + "`" + `,;{}]+)`)

// secretNamePart is a name that says it holds a secret. It's a pattern,
// not a credential.
//
//nolint:gosec // G101: a regexp for names, not a credential
const secretNamePart = `[A-Za-z0-9_.\-]*(?:api[_-]?key|token|secret|passw(?:or)?d|pwd|private[_-]?key|access[_-]?key|credential)[A-Za-z0-9_\-]*`

var secretNameRe = regexp.MustCompile(`(?i)^` + secretNamePart + `$`)

// SecretName says whether a name, like an env var's, says it holds a
// secret: the same rule that masks NAME=value, without the names that are
// about a secret rather than one (TOKEN_PATH, apiKeyHelper, PWD).
func SecretName(name string) bool {
	return secretNameRe.MatchString(name) && !aboutASecret(strings.ToLower(name))
}

// aboutASecret reports whether a name holds something about a secret
// rather than the secret itself, like apiKeyHelper, token_path or
// password_required. PWD and OLDPWD are the shell's working dirs, so an
// env dump has them.
func aboutASecret(name string) bool {
	if name == "pwd" || name == "oldpwd" {
		return true
	}
	for _, s := range []string{
		"helper", "path", "file", "dir", "name", "id", "url", "env", "var",
		"command", "cmd", "flag", "required", "type", "count", "limit", "ttl",
		"expiry", "expires", "header", "prefix", "tokens", "process", "source",
	} {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// aSettingValue reports whether a value is a setting, not a secret.
func aSettingValue(v string) bool {
	switch strings.ToLower(v) {
	case "true", "false", "null", "none", "nil", "yes", "no", "on", "off":
		return true
	}
	return false
}

var allDigits = regexp.MustCompile(`^[0-9]+$`)

func namedValid(match, value string) bool {
	name := strings.ToLower(namedRe.FindStringSubmatch(match)[namedRe.SubexpIndex("name")])
	if aboutASecret(name) || aSettingValue(value) {
		return false
	}
	// A short number is a setting like max_tokens, not a secret.
	if allDigits.MatchString(value) && len(value) < 16 {
		return false
	}
	return notAReference(match, value)
}

// notAReference drops values that point at a secret instead of holding
// it, like $API_KEY, ${API_KEY} or %API_KEY%.
func notAReference(_, value string) bool {
	return !strings.HasPrefix(value, "$") && (!strings.HasPrefix(value, "%") || !strings.HasSuffix(value, "%"))
}

// longValue is the length from which entropy can judge a value. Below it,
// entropy per char is capped by log2 of the length, so a short real
// password would always look like a placeholder.
const longValue = 16

// namedPlaceholder judges a value from the name rule by its shape: words
// people put in examples, an <angle bracket> hole, or one char repeated.
// Only long values also get the entropy check.
func namedPlaceholder(value string) bool {
	v := strings.ToLower(value)
	for _, w := range []string{"example", "placeholder", "changeme", "change_me", "your", "xxx", "dummy", "redacted"} {
		if strings.Contains(v, w) {
			return true
		}
	}
	if strings.HasPrefix(v, "<") || strings.Trim(v, v[:1]) == "" {
		return true
	}
	return len(value) >= longValue && redact.Entropy(value) < minEntropy
}
