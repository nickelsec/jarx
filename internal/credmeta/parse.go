package credmeta

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Fact is one piece of safe metadata about a credential: a profile name, a
// host, whether a key has a passphrase. Never a credential value.
type Fact struct {
	Key   string
	Value string
}

// MaxParseSize is the most a parser reads from one credential file. The
// files jarx reads metadata from are small; a bigger one is cut off, and its
// parser works with what it got.
const MaxParseSize = 1 << 20

// ErrNotRead means a kind or file is only checked for existence.
var ErrNotRead = errors.New("credential checked for existence only, not read")

// parsers read metadata, by kind. A kind that isn't here is existence only.
//
//nolint:gochecknoglobals // fixed table, read only
var parsers = map[string]func(rel string, r io.Reader) ([]Fact, error){
	KindAWS:     parseAWS,
	KindGH:      parseGH,
	KindDocker:  parseDocker,
	KindKube:    parseKube,
	KindSSH:     parseSSH,
	KindGit:     parseGitCredentials,
	KindNetrc:   parseNetrc,
	KindNpm:     parseNpmrc,
	KindPypi:    parsePypirc,
	KindEnvFile: parseDotenv,
}

// Reads says whether jarx reads metadata from a credential of the kind at
// rel (its path inside the credential place, or its file name). The rest
// are only checked for existence: the agents' login files, gcloud, azure
// and gnupg, and private keys outside ~/.ssh. A place can also be existence only, like
// aws's token caches (Place.NoRead).
func Reads(kind, _ string) bool {
	_, ok := parsers[kind]
	return ok
}

// Parse reads the safe metadata of a credential file of the kind, and
// nothing else. It reads at most MaxParseSize from r.
func Parse(kind, rel string, r io.Reader) ([]Fact, error) {
	if !Reads(kind, rel) {
		return nil, fmt.Errorf("%s: %w", kind, ErrNotRead)
	}
	return parsers[kind](rel, io.LimitReader(r, MaxParseSize))
}

// lineBuffer is the line scanner's starting buffer; it grows up to
// MaxParseSize for a long line.
const lineBuffer = 64 << 10

// lines calls fn for each line of r, without its line ending.
func lines(r io.Reader, fn func(line string)) error {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, lineBuffer), MaxParseSize)
	for s.Scan() {
		fn(strings.TrimRight(s.Text(), "\r"))
	}
	if err := s.Err(); err != nil {
		return fmt.Errorf("reading: %w", err)
	}
	return nil
}

// name is a value jarx keeps as a name: printable, no spaces, and short.
// Anything else is dropped rather than shown.
var name = regexp.MustCompile(`^[A-Za-z0-9._@:/+-]{1,128}$`)

func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
		return v[1 : len(v)-1]
	}
	return v
}
