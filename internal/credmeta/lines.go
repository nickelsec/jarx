package credmeta

import (
	"io"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// parseGitCredentials keeps the scheme and host of each stored URL. A line
// that isn't a URL, or whose user info hides the host, is dropped whole.
func parseGitCredentials(_ string, r io.Reader) ([]Fact, error) {
	var out []Fact
	err := lines(r, func(line string) {
		u, err := url.Parse(strings.TrimSpace(line))
		if err != nil || u.Scheme == "" || u.Host == "" || !name.MatchString(u.Host) {
			return // the error text can hold the line, so it's never kept
		}
		out = append(out, Fact{"url", u.Scheme + "://" + u.Host})
	})
	return out, err
}

var envKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)

// parseDotenv keeps key names, never values.
func parseDotenv(_ string, r io.Reader) ([]Fact, error) {
	var out []Fact
	err := lines(r, func(line string) {
		t := strings.TrimSpace(line)
		if t == "" || t[0] == '#' {
			return
		}
		k, _, ok := strings.Cut(strings.TrimPrefix(t, "export "), "=")
		if k = strings.TrimSpace(k); ok && envKey.MatchString(k) {
			out = append(out, Fact{"key", k})
		}
	})
	return out, err
}

// parseNetrc keeps machine names and "default". It reads tokens the way
// curl does, with double-quoted strings, and skips the token after login,
// password and account, and a macdef's body up to a blank line.
func parseNetrc(_ string, r io.Reader) ([]Fact, error) {
	var n netrcReader
	err := lines(r, func(line string) {
		if n.inMacro {
			n.inMacro = strings.TrimSpace(line) != ""
			return
		}
		for _, tok := range netrcTokens(line) {
			n.token(tok)
		}
	})
	return n.out, err
}

const (
	netrcMachine = "machine"
	netrcMacdef  = "macdef"
)

type netrcReader struct {
	out     []Fact
	skip    bool   // the next token is a login, password or account value
	next    string // the keyword whose value comes next
	inMacro bool
}

func (n *netrcReader) token(tok string) {
	if n.skip {
		n.skip = false
		return
	}
	switch n.next {
	case netrcMachine:
		if name.MatchString(tok) {
			n.out = append(n.out, Fact{netrcMachine, tok})
		}
		n.next = ""
	case netrcMacdef:
		n.inMacro, n.next = true, "" // the body starts on the next line
	default:
		n.keyword(tok)
	}
}

// keyword reads a token that isn't a machine or macdef value.
func (n *netrcReader) keyword(tok string) {
	switch tok {
	case netrcMachine, netrcMacdef:
		n.next = tok
	case "default":
		n.out = append(n.out, Fact{netrcMachine, "default"})
	case "login", keyPassword, "account":
		n.skip = true
	}
}

// netrcTokens splits a line at spaces, keeping a double-quoted string, with
// \ escapes, as one token.
func netrcTokens(line string) []string {
	var t tokenizer
	for _, r := range line {
		t.rune(r)
	}
	t.flush()
	return t.out
}

type tokenizer struct {
	out                   []string
	cur                   strings.Builder
	quoted, escaped, have bool
}

func (t *tokenizer) rune(r rune) {
	switch {
	case t.escaped:
		t.cur.WriteRune(r)
		t.escaped = false
	case t.quoted && r == '\\':
		t.escaped = true
	case r == '"':
		t.quoted, t.have = !t.quoted, true
	case !t.quoted && unicode.IsSpace(r):
		t.flush()
	default:
		t.cur.WriteRune(r)
		t.have = true
	}
}

func (t *tokenizer) flush() {
	if t.have {
		t.out, t.have = append(t.out, t.cur.String()), false
		t.cur.Reset()
	}
}
