// Package claude is the Claude Code adapter.
//
// Project records come from the "projects" map in ~/.claude.json (moved by
// CLAUDE_CONFIG_DIR, like ~/.claude/). The docs show that map keyed by
// project path, at code.claude.com/docs/en/claude-directory. The one field
// read inside an entry is hasTrustDialogAccepted, which
// code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder
// documents as the folder's trust. Every other value is dropped.
package claude

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
)

// maxConfigSize caps how much of ~/.claude.json is read. It holds history,
// so it can outgrow fsys's 10 MiB ReadFile cap; it's streamed instead.
const maxConfigSize = 100 << 20

var errTooLarge = errors.New("too large")

// Adapter is the Claude Code adapter.
type Adapter struct{}

// Agent returns claude.
func (Adapter) Agent() model.Agent { return model.AgentClaude }

// Name is how the scan names the agent.
func (Adapter) Name() string { return "Claude Code" }

// ConfigDir is ~/.claude, or CLAUDE_CONFIG_DIR.
func (Adapter) ConfigDir(env platform.Env) string { return claudeDir(env) }

// Projects returns the paths in the projects map of ~/.claude.json.
func (Adapter) Projects(c agent.Context) ([]model.Project, []finding.Finding) {
	file := configFile(c.Env)
	origin := model.Origin{
		Agent:    model.AgentClaude,
		File:     model.NewPath(c.Scrub, file),
		Scope:    model.ScopeUser,
		InEffect: true,
	}
	unreadable := func(why string) []finding.Finding {
		ev, _ := c.Scrub.Scrub(why)
		return []finding.Finding{finding.UnreadableRecord().New(origin, ev)}
	}

	r, err := c.Files.Open(file)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, unreadable("couldn't open the file")
	}
	defer func() { _ = r.Close() }()

	recs, err := projectRecords(r, maxConfigSize)
	var perr parseError
	switch {
	case errors.Is(err, errTooLarge):
		return nil, finding.FromSkips(c.Scrub, []fsys.Skip{{Path: file, Size: maxConfigSize + 1, Reason: "too large"}})
	case errors.As(err, &perr):
		return nil, unreadable(perr.Error())
	case err != nil:
		return nil, unreadable("couldn't read the file")
	}

	out := make([]model.Project, 0, len(recs))
	for _, rec := range recs {
		out = append(out, model.Project{
			Path:    model.NewPath(c.Scrub, c.Env.MapPath(rec.path)),
			Origins: []model.Origin{origin},
			Trust:   []model.Trust{{Level: rec.trust, Origin: origin}},
		})
	}
	return out, nil
}

func configFile(env platform.Env) string {
	if dir, ok := env.Lookup("CLAUDE_CONFIG_DIR"); ok && dir != "" {
		return filepath.Join(env.MapPath(dir), ".claude.json")
	}
	return filepath.Join(env.Home, ".claude.json")
}

// record is one entry of the projects map: its path and trust.
type record struct {
	path  string
	trust model.TrustLevel
}

// trustKey is the one field read inside a project entry.
const trustKey = "hasTrustDialogAccepted"

// projectRecords streams JSON from r and returns the entries of the top-level
// "projects" object. Inside an entry only hasTrustDialogAccepted is kept, and
// anything but a bool there is unknown trust. Every other value is read past
// and dropped, so nothing else in the file (like an MCP server's env token)
// is kept. It reads at most limit bytes.
func projectRecords(r io.Reader, limit int64) ([]record, error) {
	j := jsonReader{dec: json.NewDecoder(&capReader{r: r, left: limit})}
	if err := j.expect('{', "the file isn't a JSON object"); err != nil {
		return nil, err
	}
	var recs []record
	for j.dec.More() {
		key, err := j.key()
		if err != nil {
			return nil, err
		}
		var got []record
		if key == "projects" {
			got, err = j.projects()
		} else {
			err = j.skip()
		}
		if err != nil {
			return nil, err
		}
		recs = append(recs, got...)
	}
	if err := j.expect('}', "the file isn't closed"); err != nil {
		return nil, err
	}
	return recs, nil
}

// parseError says where parsing failed, never what was there.
type parseError struct {
	offset int64
	why    string
}

func (e parseError) Error() string { return fmt.Sprintf("%s (near byte %d)", e.why, e.offset) }

// jsonReader walks JSON tokens. Its errors are errTooLarge or a parseError
// with no file content in it.
type jsonReader struct {
	dec *json.Decoder
}

func (j jsonReader) fail(why string) error {
	return parseError{offset: j.dec.InputOffset(), why: why}
}

// readErr keeps errTooLarge and turns every other read or syntax error into
// a parseError.
func (j jsonReader) readErr(err error) error {
	if errors.Is(err, errTooLarge) {
		return err
	}
	return j.fail("not valid JSON")
}

func (j jsonReader) expect(want json.Delim, why string) error {
	tok, err := j.dec.Token()
	if err != nil {
		return j.readErr(err)
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return j.fail(why)
	}
	return nil
}

func (j jsonReader) key() (string, error) {
	tok, err := j.dec.Token()
	if err != nil {
		return "", j.readErr(err)
	}
	key, ok := tok.(string)
	if !ok {
		return "", j.fail("expected a key")
	}
	return key, nil
}

// projects reads the projects object.
func (j jsonReader) projects() ([]record, error) {
	if err := j.expect('{', "projects isn't a JSON object"); err != nil {
		return nil, err
	}
	var recs []record
	for j.dec.More() {
		path, err := j.key()
		if err != nil {
			return nil, err
		}
		trust, err := j.entryTrust()
		if err != nil {
			return nil, err
		}
		recs = append(recs, record{path: path, trust: trust})
	}
	if err := j.expect('}', "object isn't closed"); err != nil {
		return nil, err
	}
	return recs, nil
}

// entryTrust reads one project entry and returns its trust. A value that
// isn't an object is skipped and its trust is unknown.
func (j jsonReader) entryTrust() (model.TrustLevel, error) {
	tok, err := j.dec.Token()
	if err != nil {
		return "", j.readErr(err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return model.TrustUnknown, j.dropRest(tok)
	}
	trust := model.TrustUnknown
	for j.dec.More() {
		k, err := j.key()
		if err != nil {
			return "", err
		}
		if k != trustKey {
			err = j.skip()
		} else {
			trust, err = j.trustValue()
		}
		if err != nil {
			return "", err
		}
	}
	if err := j.expect('}', "object isn't closed"); err != nil {
		return "", err
	}
	return trust, nil
}

// dropRest drops the rest of a value whose first token was tok: the rest of
// a list, or nothing for a plain value.
func (j jsonReader) dropRest(tok json.Token) error {
	if d, ok := tok.(json.Delim); ok && d == '[' {
		return j.skipRest(1)
	}
	return nil
}

// trustValue reads the hasTrustDialogAccepted value. Only a bool counts;
// anything else is unknown trust and is skipped.
func (j jsonReader) trustValue() (model.TrustLevel, error) {
	tok, err := j.dec.Token()
	if err != nil {
		return "", j.readErr(err)
	}
	switch v := tok.(type) {
	case bool:
		if v {
			return model.TrustTrusted, nil
		}
		return model.TrustUntrusted, nil
	case json.Delim:
		return model.TrustUnknown, j.skipRest(1)
	default:
		return model.TrustUnknown, nil
	}
}

// skip reads one value and drops it.
func (j jsonReader) skip() error { return j.skipRest(0) }

// skipRest drops tokens until depth open objects and arrays are closed. With
// depth 0 it drops exactly one value.
func (j jsonReader) skipRest(depth int) error {
	for {
		tok, err := j.dec.Token()
		if err != nil {
			return j.readErr(err)
		}
		if d, ok := tok.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else {
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}

// capReader returns errTooLarge after left bytes.
type capReader struct {
	r    io.Reader
	left int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, errTooLarge
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err //nolint:wrapcheck // io.EOF must reach the decoder unwrapped
}
