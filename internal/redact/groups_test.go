package redact

import (
	"regexp"
	"strings"
	"testing"
)

func TestASecretGroupMasksOnlyThatPart(t *testing.T) {
	s, err := New([]Pattern{{
		Kind: "named_secret",
		Re:   regexp.MustCompile(`(?i)[a-z_]*token[a-z_]*\s*=\s*(?P<secret>\S+)`),
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	got, found := s.Scrub("export DEPLOY_TOKEN=abc123xyz and more")

	if got.String() != "export DEPLOY_TOKEN=REDACTED:named_secret and more" {
		t.Errorf("Scrub() = %q, want only the value masked", got)
	}
	if len(found) != 1 || found[0].Kind != "named_secret" {
		t.Errorf("found = %+v", found)
	}
}

func TestValidDropsMatchesThatArentSecrets(t *testing.T) {
	s, err := New([]Pattern{{
		Kind:  "named_secret",
		Re:    regexp.MustCompile(`(?i)[a-z_]*token[a-z_]*\s*=\s*(?P<secret>\S+)`),
		Valid: func(_, value string) bool { return strings.ContainsAny(value, "abcdefghijklmnopqrstuvwxyz") },
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	got, found := s.Scrub("max_tokens=100000 and API_TOKEN=s3cr3tvalue")

	if got.String() != "max_tokens=100000 and API_TOKEN=REDACTED:named_secret" || len(found) != 1 {
		t.Errorf("Scrub() = %q, %+v; want only the value with letters masked", got, found)
	}
}

func TestEqualOverlapsTakeTheFirstListedKind(t *testing.T) {
	// Both match the same span. The more specific pattern is listed first,
	// so its kind must win every time, not by sort luck.
	s, err := New([]Pattern{
		{Kind: "specific", Re: regexp.MustCompile(`sk-ant-[a-z0-9]{8}`)},
		{Kind: "general", Re: regexp.MustCompile(`sk-[a-z0-9-]{12}`)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	for range 50 {
		if got, _ := s.Scrub("sk-ant-abcd1234"); got.String() != "REDACTED:specific" {
			t.Fatalf("Scrub() = %q, want the first listed kind", got)
		}
	}
}

func TestTextKeepsWhatWasMaskedButNotTheValue(t *testing.T) {
	s, err := New(testPatterns(), staticKey("k"))
	if err != nil {
		t.Fatal(err)
	}

	got, _ := s.Scrub("a " + canaryToken + " and " + canaryKey)
	plain, _ := s.Scrub("nothing here")

	secrets := got.Secrets()
	if len(secrets) != 2 || secrets[0].Kind != "test_token" || secrets[1].Kind != "test_key" || secrets[0].Fingerprint == "" {
		t.Errorf("Secrets() = %+v, want both, in order, with fingerprints", secrets)
	}
	if len(plain.Secrets()) != 0 {
		t.Errorf("plain Secrets() = %+v, want none", plain.Secrets())
	}
	for _, f := range secrets {
		if strings.Contains(f.Kind+f.Fingerprint, canaryToken) {
			t.Error("a Found holds the value")
		}
	}
}

func TestNewRejectsASecretGroupThatDoesntExist(t *testing.T) {
	_, err := New([]Pattern{{Kind: "x", Re: regexp.MustCompile(`a(?P<other>b)`), Group: "secret"}}, nil)
	if err == nil {
		t.Error("New() error = nil, want one for a named group the regexp lacks")
	}
}

func TestAPatternCanDecideWhatLooksLikeAPlaceholder(t *testing.T) {
	// Entropy per char can't beat log2(len), so a short real password always
	// looks low. A pattern can judge by shape instead.
	s, err := New([]Pattern{{
		Kind:        "named_secret",
		Re:          regexp.MustCompile(`pw=(?P<secret>\S+)`),
		MinEntropy:  3.0,
		Placeholder: func(v string) bool { return strings.Contains(v, "example") },
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, found := s.Scrub("pw=hunter2 pw=example-long-value")

	if len(found) != 2 || found[0].LikelyPlaceholder || !found[1].LikelyPlaceholder {
		t.Errorf("found = %+v, want the short real value not flagged and the example flagged", found)
	}
}

func TestAMaskIsNeverMaskedAgain(t *testing.T) {
	// Text read back from a snapshot goes through Scrub again. A pattern
	// that would match inside an existing mask must leave it alone.
	s, err := New([]Pattern{{Kind: "kv", Re: regexp.MustCompile(`key=(?P<secret>\S+)`)}}, staticKey("k"))
	if err != nil {
		t.Fatal(err)
	}

	once, _ := s.Scrub("key=abc123 and key=REDACTED:kv")
	twice, found := s.Scrub(once.String())

	if twice.String() != once.String() || len(found) != 0 || !strings.Contains(once.String(), "key=REDACTED:kv") {
		t.Errorf("once %q, twice %q (%d finds); want masks left as they are", once, twice, len(found))
	}
}
