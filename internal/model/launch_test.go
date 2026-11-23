package model

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

const launchCanary = "launch-canary-Zq81"

func TestLaunchGivesTheSpecOnlyToSpec(t *testing.T) {
	l := NewLaunch(LaunchSpec{Command: "srv", Args: []string{"--key", launchCanary}, Env: [][2]string{{"TOKEN", launchCanary}}})

	spec, ok := l.Spec()

	if !ok || spec.Command != "srv" || !slices.Equal(spec.Args, []string{"--key", launchCanary}) {
		t.Errorf("Spec() = %+v, %v; want the raw spec", spec, ok)
	}
	if _, ok := (Launch{}).Spec(); ok {
		t.Error("the zero Launch has a spec")
	}
}

func TestLaunchNeverPrintsOrEncodesTheSpec(t *testing.T) {
	l := NewLaunch(LaunchSpec{Command: launchCanary, URL: "https://x/?t=" + launchCanary, Headers: [][2]string{{"Authorization", launchCanary}}})
	s := Server{Launch: l}
	//nolint:musttag // only checking nothing raw comes out
	b, err := json.Marshal(struct {
		L Launch `json:"l"`
		S Server `json:"s"`
	}{l, s})
	if err != nil {
		t.Fatal(err)
	}

	for form, out := range map[string]string{
		"%v": fmt.Sprintf("%v", l), "%s": fmt.Sprintf("%s", l), "%+v": fmt.Sprintf("%+v", l),
		"%#v": fmt.Sprintf("%#v", l), "%q": fmt.Sprintf("%q", l), "%x": fmt.Sprintf("%x", l),
		"server %+v": fmt.Sprintf("%+v", s), "server %#v": fmt.Sprintf("%#v", s),
		"pointer %+v": fmt.Sprintf("%+v", &s), "json": string(b),
	} {
		if strings.Contains(out, launchCanary) {
			t.Errorf("%s leaks the launch spec: %s", form, out)
		}
	}
}
