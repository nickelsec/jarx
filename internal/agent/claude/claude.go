// Package claude is the Claude Code adapter.
//
// Project records come from the "projects" map in ~/.claude.json (moved by
// CLAUDE_CONFIG_DIR, like ~/.claude/). The docs show that map keyed by
// project path, at code.claude.com/docs/en/claude-directory, but not the
// fields inside an entry, so only the keys are read here.
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

	keys, err := projectKeys(r, maxConfigSize)
	var perr parseError
	switch {
	case errors.Is(err, errTooLarge):
		return nil, finding.FromSkips(c.Scrub, []fsys.Skip{{Path: file, Size: maxConfigSize + 1, Reason: "too large"}})
	case errors.As(err, &perr):
		return nil, unreadable(perr.Error())
	case err != nil:
		return nil, unreadable("couldn't read the file")
	}

	out := make([]model.Project, 0, len(keys))
	for _, k := range keys {
		out = append(out, model.Project{
			Path:    model.NewPath(c.Scrub, c.Env.MapPath(k)),
			Origins: []model.Origin{origin},
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

// projectKeys streams JSON from r and returns the keys of the top-level
// "projects" object. Every value is read past and dropped, so nothing else in
// the file (like an MCP server's env token) is kept. It reads at most limit
// bytes.
func projectKeys(r io.Reader, limit int64) ([]string, error) {
	j := jsonReader{dec: json.NewDecoder(&capReader{r: r, left: limit})}
	if err := j.expect('{', "the file isn't a JSON object"); err != nil {
		return nil, err
	}
	var keys []string
	for j.dec.More() {
		key, err := j.key()
		if err != nil {
			return nil, err
		}
		var got []string
		if key == "projects" {
			got, err = j.objectKeys("projects isn't a JSON object")
		} else {
			err = j.skip()
		}
		if err != nil {
			return nil, err
		}
		keys = append(keys, got...)
	}
	if err := j.expect('}', "the file isn't closed"); err != nil {
		return nil, err
	}
	return keys, nil
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

// objectKeys reads an object and returns its keys, dropping every value.
func (j jsonReader) objectKeys(notObject string) ([]string, error) {
	if err := j.expect('{', notObject); err != nil {
		return nil, err
	}
	var keys []string
	for j.dec.More() {
		k, err := j.key()
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
		if err := j.skip(); err != nil {
			return nil, err
		}
	}
	if err := j.expect('}', "object isn't closed"); err != nil {
		return nil, err
	}
	return keys, nil
}

// skip reads one value and drops it.
func (j jsonReader) skip() error {
	depth := 0
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
