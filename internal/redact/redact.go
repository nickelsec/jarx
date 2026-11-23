// Package redact is where every string jarx shows, stores or sends gets
// masked. A Text can only be built here, so code that takes a Text can't be
// handed a raw string.
//
// Anything that matches a pattern is always masked. Entropy only decides
// whether a match is flagged as a likely placeholder, never whether it gets
// masked: showing a real secret is far worse than hiding a fake one.
package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
)

// Text is a string that went through a Scrubber. Its zero value is "".
// It also keeps what was masked in it (kinds and fingerprints, never the
// values), so analyzers can work from the masked text alone.
type Text struct {
	s     string
	found []Found
}

// Secrets returns what was masked in t, in order.
func (t Text) Secrets() []Found { return append([]Found(nil), t.found...) }

// String returns the masked string.
func (t Text) String() string { return t.s }

// MarshalJSON encodes the masked string.
func (t Text) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(t.s)
	if err != nil {
		return nil, fmt.Errorf("encoding text: %w", err)
	}
	return b, nil
}

// IsZero reports whether t is empty.
func (t Text) IsZero() bool { return t.s == "" }

// Pattern finds one kind of secret.
type Pattern struct {
	Kind       string         // lowercase with underscores, like github_pat
	Re         *regexp.Regexp // what to mask
	MinEntropy float64        // bits per char; a match below it is LikelyPlaceholder
	// Group names the part of a match to mask, like the value in
	// KEY=value. It defaults to a group named "secret" when Re has one,
	// else the whole match is masked.
	Group string
	// Valid, when set, drops matches that aren't secrets. It gets the whole
	// match and the part that would be masked.
	Valid func(match, value string) bool
	// Placeholder, when set, decides LikelyPlaceholder instead of
	// MinEntropy. Entropy per char can't beat log2 of the length, so short
	// values need a check by shape.
	Placeholder func(value string) bool
}

// placeholder reports whether a masked value looks like a placeholder.
func (p Pattern) placeholder(value string) bool {
	if p.Placeholder != nil {
		return p.Placeholder(value)
	}
	return Entropy(value) < p.MinEntropy
}

// defaultGroup is the group masked when a pattern doesn't name one.
const defaultGroup = "secret"

// groupIndex is the submatch to mask, or 0 for the whole match.
func (p Pattern) groupIndex() int {
	name := p.Group
	if name == "" {
		name = defaultGroup
	}
	if i := p.Re.SubexpIndex(name); i > 0 {
		return i
	}
	return 0
}

// Found describes one masked secret. It never holds the value.
type Found struct {
	Kind              string
	Fingerprint       string // 12 hex chars, "" when no key is available
	LikelyPlaceholder bool
}

// KeySource gives the per-install fingerprint key.
type KeySource interface {
	Key() ([]byte, error)
}

// Scrubber masks secrets. It's safe for concurrent use.
type Scrubber struct {
	patterns []Pattern
	masks    *regexp.Regexp // the masks this scrubber writes, so it never masks one again

	keys    KeySource
	keyOnce sync.Once
	key     []byte
	keyErr  error
}

var kindRe = regexp.MustCompile(`^[a-z0-9_]+$`)

// fallbackKind is used by Secret when the caller passes a bad kind.
const fallbackKind = "secret"

// New returns a Scrubber. keys may be nil, which masks without fingerprints.
func New(patterns []Pattern, keys KeySource) (*Scrubber, error) {
	for i, p := range patterns {
		if !kindRe.MatchString(p.Kind) {
			return nil, fmt.Errorf("pattern %d: kind %q must be lowercase letters, digits and underscores", i, p.Kind)
		}
		if p.Re == nil {
			return nil, fmt.Errorf("pattern %d (%s): no regexp", i, p.Kind)
		}
		if p.Group != "" && p.Re.SubexpIndex(p.Group) < 0 {
			return nil, fmt.Errorf("pattern %d (%s): no group named %q", i, p.Kind, p.Group)
		}
	}
	return &Scrubber{patterns: patterns, keys: keys, masks: maskPattern(patterns)}, nil
}

// KeyErr returns the error from loading the fingerprint key, if any. When
// it's set, masks have no fingerprint.
func (s *Scrubber) KeyErr() error {
	s.loadKey()
	return s.keyErr
}

type span struct {
	start, end int
	pattern    int
}

// Scrub masks every pattern match in raw and reports what it masked.
func (s *Scrubber) Scrub(raw string) (Text, []Found) {
	spans := s.matches(raw)
	if len(spans) == 0 {
		return Text{s: raw}, nil
	}

	// Merge overlapping matches. The kind comes from the longest match in
	// each merged run, and on a tie from the pattern listed first.
	sort.SliceStable(spans, func(a, b int) bool {
		if spans[a].start != spans[b].start {
			return spans[a].start < spans[b].start
		}
		return spans[a].end-spans[a].start > spans[b].end-spans[b].start
	})
	merged := []span{spans[0]}
	longest := []int{spans[0].end - spans[0].start}
	for _, sp := range spans[1:] {
		last := &merged[len(merged)-1]
		if sp.start < last.end {
			if sp.end-sp.start > longest[len(longest)-1] {
				last.pattern = sp.pattern
				longest[len(longest)-1] = sp.end - sp.start
			}
			last.end = max(last.end, sp.end)
			continue
		}
		merged = append(merged, sp)
		longest = append(longest, sp.end-sp.start)
	}

	var b strings.Builder
	found := make([]Found, 0, len(merged))
	prev := 0
	for _, sp := range merged {
		p := s.patterns[sp.pattern]
		value := raw[sp.start:sp.end]
		f := Found{
			Kind:              p.Kind,
			Fingerprint:       s.fingerprint(value),
			LikelyPlaceholder: p.placeholder(value),
		}
		b.WriteString(raw[prev:sp.start])
		b.WriteString(mask(f))
		found = append(found, f)
		prev = sp.end
	}
	b.WriteString(raw[prev:])
	return Text{s: b.String(), found: found}, found
}

// Secret masks all of raw, for values the caller already knows are secret,
// like an MCP env value or an Authorization header. An empty value gives an
// empty Text. A bad kind falls back to "secret".
func (s *Scrubber) Secret(kind, raw string) (Text, Found) {
	if raw == "" {
		return Text{}, Found{}
	}
	if !kindRe.MatchString(kind) {
		kind = fallbackKind
	}
	f := Found{Kind: kind, Fingerprint: s.fingerprint(raw)}
	return Text{s: mask(f), found: []Found{f}}, f
}

// matches finds every span to mask, in pattern order.
func (s *Scrubber) matches(raw string) []span {
	var spans []span
	masks := s.ownMasks(raw)
	for i, p := range s.patterns {
		g := p.groupIndex()
		for _, m := range p.Re.FindAllStringSubmatchIndex(raw, -1) {
			start, end := m[2*g], m[2*g+1]
			if start < 0 || end <= start {
				continue
			}
			if p.Valid != nil && !p.Valid(raw[m[0]:m[1]], raw[start:end]) {
				continue
			}
			if overlaps(masks, start, end) {
				continue // already masked, like text read back from a snapshot
			}
			spans = append(spans, span{start, end, i})
		}
	}
	return spans
}

// maskPattern matches a mask this scrubber writes: REDACTED, one of its
// kinds, maybe a fingerprint. Longer kinds go first, so a kind that's the
// start of another one can't cut a match short.
func maskPattern(patterns []Pattern) *regexp.Regexp {
	kinds := []string{fallbackKind}
	for _, p := range patterns {
		if !slices.Contains(kinds, p.Kind) {
			kinds = append(kinds, p.Kind)
		}
	}
	sort.Slice(kinds, func(a, b int) bool { return len(kinds[a]) > len(kinds[b]) })
	return regexp.MustCompile(`REDACTED:(?:` + strings.Join(kinds, "|") + `)(?::[0-9a-f]{12})?`)
}

// ownMasks finds the masks already in raw. One counts only when it ends at
// a word boundary, so text made to look like a mask, like REDACTED:ghp_ with
// a real token after it, can't hide that token.
func (s *Scrubber) ownMasks(raw string) [][]int {
	var out [][]int
	for _, m := range s.masks.FindAllStringIndex(raw, -1) {
		if m[1] < len(raw) && isWordByte(raw[m[1]]) {
			continue
		}
		out = append(out, m)
	}
	return out
}

func isWordByte(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func overlaps(spans [][]int, start, end int) bool {
	for _, m := range spans {
		if start < m[1] && m[0] < end {
			return true
		}
	}
	return false
}

func mask(f Found) string {
	if f.Fingerprint == "" {
		return "REDACTED:" + f.Kind
	}
	return "REDACTED:" + f.Kind + ":" + f.Fingerprint
}

// fingerprintLen is 12 hex chars, 48 bits of the HMAC.
const fingerprintLen = 12

func (s *Scrubber) fingerprint(value string) string {
	key := s.loadKey()
	if key == nil {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))[:fingerprintLen]
}

// loadKey gets the key once, the first time a fingerprint is needed.
func (s *Scrubber) loadKey() []byte {
	if s.keys == nil {
		return nil
	}
	s.keyOnce.Do(func() {
		s.key, s.keyErr = s.keys.Key()
		if s.keyErr != nil {
			s.key = nil
		}
	})
	return s.key
}

// Entropy is the Shannon entropy of v in bits per byte.
func Entropy(v string) float64 {
	if v == "" {
		return 0
	}
	var counts [256]int
	for i := range len(v) {
		counts[v[i]]++
	}
	var h float64
	n := float64(len(v))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}
