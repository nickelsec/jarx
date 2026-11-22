package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/redact"
)

const canary = "tok_Xq7Lm2Pz9Rw4Tb8Nc1Vd" // made up for tests

func scrubber(t *testing.T) *redact.Scrubber {
	t.Helper()
	s, err := redact.New([]redact.Pattern{
		{Kind: "test_token", Re: regexp.MustCompile(`tok_[A-Za-z0-9]{16,}`)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPathKeepsRawForReadsAndShowsMasked(t *testing.T) {
	raw := `C:\work\` + canary + `\repo`

	p := NewPath(scrubber(t), raw)

	if p.Raw() != raw {
		t.Errorf("Raw() = %q, want the raw path", p.Raw())
	}
	if p.Text().String() != `C:\work\REDACTED:test_token\repo` {
		t.Errorf("Text() = %q, want the masked path", p.Text())
	}
	if p.IsZero() {
		t.Error("IsZero() = true for a set path")
	}
	if !(Path{}).IsZero() {
		t.Error("IsZero() = false for the zero Path")
	}
}

func TestPathNeverPrintsRaw(t *testing.T) {
	p := NewPath(scrubber(t), "/home/dev/"+canary)
	o := Origin{File: p}
	//nolint:musttag // model JSON tags come with the snapshot schema in phase 3
	b, err := json.Marshal(struct {
		P Path   `json:"p"`
		O Origin `json:"o"`
	}{p, o})
	if err != nil {
		t.Fatal(err)
	}

	for form, out := range map[string]string{
		"%v":          fmt.Sprintf("%v", p),
		"%s":          fmt.Sprintf("%s", p),
		"%+v":         fmt.Sprintf("%+v", p),
		"%#v":         fmt.Sprintf("%#v", p),
		"%q":          fmt.Sprintf("%q", p),
		"origin %+v":  fmt.Sprintf("%+v", o),
		"origin %#v":  fmt.Sprintf("%#v", o),
		"errorf":      fmt.Errorf("reading %v: %w", p, errors.New("boom")).Error(),
		"json":        string(b),
		"slice %v":    fmt.Sprintf("%v", []Path{p}),
		"pointer %+v": fmt.Sprintf("%+v", &o),
	} {
		if strings.Contains(out, canary) {
			t.Errorf("%s leaks the raw path: %s", form, out)
		}
		if !strings.Contains(out, "REDACTED:test_token") {
			t.Errorf("%s = %s, want the masked path in it", form, out)
		}
	}
}

func layer(v string, inEffect bool, scope Scope) Layer[string] {
	return Layer[string]{Value: v, Origin: Origin{Scope: scope, InEffect: inEffect}}
}

func TestSettingEffectiveIsTheFirstLayerInEffect(t *testing.T) {
	// Highest precedence first. The managed layer is out of effect (say, it
	// failed to parse), so the project layer wins over user.
	s := Setting[string]{Layers: []Layer[string]{
		layer("managed", false, ScopeManaged),
		layer("project", true, ScopeProject),
		layer("user", true, ScopeUser),
	}}

	got, ok := s.Effective()

	if !ok || got.Value != "project" {
		t.Errorf("Effective() = %+v, %v; want the project layer", got, ok)
	}
}

func TestSettingInEffectKeepsEveryLayerInEffect(t *testing.T) {
	// Lists like permissions.allow combine across scopes.
	s := Setting[string]{Layers: []Layer[string]{
		layer("a", true, ScopeProject),
		layer("b", false, ScopeLocal),
		layer("c", true, ScopeUser),
	}}

	got := s.InEffect()

	if len(got) != 2 || got[0].Value != "a" || got[1].Value != "c" {
		t.Errorf("InEffect() = %+v, want layers a and c", got)
	}
}

func TestSettingWithNothingInEffect(t *testing.T) {
	s := Setting[string]{Layers: []Layer[string]{layer("x", false, ScopeProject)}}

	if _, ok := s.Effective(); ok {
		t.Error("Effective() ok = true, want false")
	}
	if got := s.InEffect(); len(got) != 0 {
		t.Errorf("InEffect() = %+v, want none", got)
	}
}
