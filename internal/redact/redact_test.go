package redact

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/platform"
)

// staticKey is a KeySource for tests.
type staticKey []byte

func (k staticKey) Key() ([]byte, error) { return k, nil }

func testPatterns() []Pattern {
	return []Pattern{
		{Kind: "test_token", Re: regexp.MustCompile(`tok_[A-Za-z0-9]{16,}`), MinEntropy: 3.0},
		{Kind: "test_key", Re: regexp.MustCompile(`key-[a-f0-9]{24}`), MinEntropy: 3.0},
	}
}

// Fake secrets, made up for tests. Each matches one test pattern.
//
//nolint:gosec // G101: these are made-up canaries, not credentials.
const (
	canaryToken = "tok_Xq7Lm2Pz9Rw4Tb8Nc1Vd"
	canaryKey   = "key-3f9a1c2b7d4e8a0b6c5d1e2f"
)

var fpRe = regexp.MustCompile(`^[0-9a-f]{12}$`)

// fpOf returns the first find's fingerprint, or "" when nothing was found,
// so a broken scrubber fails the test instead of panicking.
func fpOf(found []Found) string {
	if len(found) == 0 {
		return ""
	}
	return found[0].Fingerprint
}

func newScrubber(t *testing.T, key KeySource) *Scrubber {
	t.Helper()
	s, err := New(testPatterns(), key)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return s
}

func TestScrubMasksAMatchWithKindAndFingerprint(t *testing.T) {
	s := newScrubber(t, staticKey("k1"))

	got, found := s.Scrub("token=" + canaryToken + " done")

	if len(found) != 1 || found[0].Kind != "test_token" || !fpRe.MatchString(found[0].Fingerprint) {
		t.Fatalf("found = %+v, want one test_token with a 12 hex fingerprint", found)
	}
	want := "token=REDACTED:test_token:" + found[0].Fingerprint + " done"
	if got.String() != want {
		t.Errorf("Scrub() = %q, want %q", got, want)
	}
	if found[0].LikelyPlaceholder {
		t.Error("LikelyPlaceholder = true for a high-entropy token")
	}
}

func TestScrubMasksLowEntropyMatchesToo(t *testing.T) {
	s := newScrubber(t, staticKey("k1"))
	placeholder := "tok_aaaaaaaaaaaaaaaa"

	got, found := s.Scrub("x " + placeholder)

	if strings.Contains(got.String(), placeholder) {
		t.Errorf("Scrub() = %q, a low-entropy match must still be masked", got)
	}
	if len(found) != 1 || !found[0].LikelyPlaceholder {
		t.Errorf("found = %+v, want one match flagged LikelyPlaceholder", found)
	}
}

func TestScrubLeavesTextWithoutSecretsAlone(t *testing.T) {
	s := newScrubber(t, staticKey("k1"))

	got, found := s.Scrub(`C:\Users\dev\.claude\settings.json`)

	if got.String() != `C:\Users\dev\.claude\settings.json` || len(found) != 0 {
		t.Errorf("Scrub() = %q, %+v; want it unchanged with no finds", got, found)
	}
}

func TestFingerprints(t *testing.T) {
	a := newScrubber(t, staticKey("key-a"))
	b := newScrubber(t, staticKey("key-b"))

	_, f1 := a.Scrub(canaryToken)
	_, f2 := a.Scrub("other text " + canaryToken)
	_, f3 := a.Scrub("tok_Yr8Mn3Qa0Sx5Uc9Od2We")
	_, f4 := b.Scrub(canaryToken)

	if fpOf(f1) == "" || fpOf(f1) != fpOf(f2) {
		t.Error("same secret, same key: fingerprints differ")
	}
	if fpOf(f1) == fpOf(f3) {
		t.Error("different secrets: same fingerprint")
	}
	if fpOf(f1) == fpOf(f4) {
		t.Error("different install keys: same fingerprint")
	}
}

func TestScrubWithoutAKeyMasksWithoutAFingerprint(t *testing.T) {
	s := newScrubber(t, nil)

	got, found := s.Scrub(canaryToken)

	if got.String() != "REDACTED:test_token" {
		t.Errorf("Scrub() = %q, want REDACTED:test_token", got)
	}
	if len(found) != 1 || found[0].Fingerprint != "" {
		t.Errorf("found = %+v, want one find with no fingerprint", found)
	}
}

func TestScrubMergesOverlapsIntoOneMask(t *testing.T) {
	patterns := []Pattern{
		{Kind: "short", Re: regexp.MustCompile(`tok_[A-Za-z0-9]{8}`)},
		{Kind: "long", Re: regexp.MustCompile(`tok_[A-Za-z0-9]{16,}`)},
	}
	s, err := New(patterns, nil)
	if err != nil {
		t.Fatal(err)
	}

	got, found := s.Scrub("a " + canaryToken + " b")

	if got.String() != "a REDACTED:long b" || len(found) != 1 {
		t.Errorf("Scrub() = %q, %+v; want one mask of the longest kind", got, found)
	}
}

func TestSecretMasksTheWholeValue(t *testing.T) {
	s := newScrubber(t, staticKey("k1"))

	got, found := s.Secret("mcp_env", "hunter2")

	if !strings.HasPrefix(got.String(), "REDACTED:mcp_env:") || strings.Contains(got.String(), "hunter2") {
		t.Errorf("Secret() = %q, want REDACTED:mcp_env:<fp>", got)
	}
	if found.Kind != "mcp_env" || !fpRe.MatchString(found.Fingerprint) {
		t.Errorf("found = %+v, want mcp_env with a fingerprint", found)
	}
}

func TestSecretEdgeCases(t *testing.T) {
	s := newScrubber(t, nil)

	if got, _ := s.Secret("mcp_env", ""); !got.IsZero() {
		t.Errorf("Secret of an empty value = %q, want zero Text", got)
	}
	if got, _ := s.Secret("Bad Kind!", "x"); got.String() != "REDACTED:secret" {
		t.Errorf("Secret with a bad kind = %q, want REDACTED:secret", got)
	}
}

func TestNewRejectsBadPatterns(t *testing.T) {
	for name, p := range map[string]Pattern{
		"bad kind":   {Kind: "Has Space", Re: regexp.MustCompile(`x`)},
		"empty kind": {Kind: "", Re: regexp.MustCompile(`x`)},
		"nil regexp": {Kind: "ok"},
	} {
		if _, err := New([]Pattern{p}, nil); err == nil {
			t.Errorf("%s: New() error = nil, want an error", name)
		}
	}
}

func TestTextZeroAndJSON(t *testing.T) {
	s := newScrubber(t, nil)
	var zero Text
	got, _ := s.Scrub("a " + canaryKey)

	if !zero.IsZero() || got.IsZero() {
		t.Error("IsZero() wrong")
	}
	b, err := json.Marshal(struct {
		V Text `json:"v"`
	}{got})
	if err != nil || string(b) != `{"v":"a REDACTED:test_key"}` {
		t.Errorf("json = %s, %v; want the masked string", b, err)
	}
}

// TestNoCanaryLeaks is the start of the no-leak suite: every canary, in every
// position, must be gone from every form a result can take.
func TestNoCanaryLeaks(t *testing.T) {
	s := newScrubber(t, staticKey("k1"))
	canaries := []string{canaryToken, canaryKey}
	for _, c := range canaries {
		for name, input := range map[string]string{
			"alone":     c,
			"start":     c + " trailing",
			"middle":    "lead " + c + " trailing",
			"end":       "lead " + c,
			"repeated":  c + " " + c + " " + c,
			"adjacent":  c + canaryKey + c,
			"multiline": "line1\n  key: " + c + "\nline3",
			"in json":   `{"env":{"TOKEN":"` + c + `"}}`,
			"in url":    "https://x.example/mcp?token=" + c,
		} {
			text, found := s.Scrub(input)
			b, err := json.Marshal(text)
			if err != nil {
				t.Fatal(err)
			}
			for form, out := range map[string]string{
				"String":      text.String(),
				"%v":          fmt.Sprintf("%v", text),
				"%+v":         fmt.Sprintf("%+v", text),
				"%#v":         fmt.Sprintf("%#v", text),
				"MarshalJSON": string(b),
				"found":       fmt.Sprintf("%+v", found),
			} {
				for _, leak := range canaries {
					if strings.Contains(out, leak) {
						t.Errorf("%s/%s: %s leaks a canary: %s", c[:4], name, form, out)
					}
				}
			}
		}
	}
}

func TestKeyFromStateIsLazyAndPersistent(t *testing.T) {
	env, err := platform.FromHome(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(env.StateDir, "fingerprint.key")

	s := newScrubber(t, KeyFromState(env))
	s.Scrub("nothing secret here")
	if _, err := os.Stat(env.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state dir exists before any secret was found (err %v)", err)
	}

	_, first := s.Scrub(canaryToken)
	data, err := os.ReadFile(keyPath) //nolint:gosec // G304: test temp path
	if err != nil || len(data) != 32 {
		t.Fatalf("key file = %d bytes, %v; want 32 bytes after the first secret", len(data), err)
	}
	if info, _ := os.Stat(keyPath); runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %v, want 0600", info.Mode().Perm())
	}

	_, again := newScrubber(t, KeyFromState(env)).Scrub(canaryToken)
	if fpOf(first) == "" || fpOf(again) != fpOf(first) {
		t.Error("a new scrubber on the same state dir gave a different fingerprint")
	}
}

func TestDamagedKeyIsAnErrorNotReplaced(t *testing.T) {
	env, err := platform.FromHome(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(env.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(env.StateDir, "fingerprint.key")
	if err := os.WriteFile(keyPath, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newScrubber(t, KeyFromState(env))

	got, _ := s.Scrub(canaryToken)

	if got.String() != "REDACTED:test_token" {
		t.Errorf("Scrub() = %q, want a mask without a fingerprint", got)
	}
	if err := s.KeyErr(); err == nil || !strings.Contains(err.Error(), "delete") {
		t.Errorf("KeyErr() = %v, want an error that says to delete the key", err)
	}
	if data, _ := os.ReadFile(keyPath); string(data) != "short" { //nolint:gosec // G304: test temp path
		t.Error("the damaged key was replaced, want it left alone")
	}
}
