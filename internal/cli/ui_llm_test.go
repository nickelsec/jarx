package cli

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nickelsec/jarx/internal/llm"
	"github.com/nickelsec/jarx/internal/ui"
)

// keyApp starts the dashboard's app on home with the LLM key set in its
// terminal, or not.
func keyApp(t *testing.T, home string, withKey bool) *uiApp {
	t.Helper()
	st := streams{lookupKey: func(name string) (string, bool) {
		if withKey && name == "JARX_LLM_KEY" {
			return canaryLLMKey, true
		}
		return "", false
	}}
	p := testPrinter()
	ss, ok := openScan(p, scanFlags{home: home}, st)
	if !ok {
		t.Fatal("openScan failed")
	}
	t.Cleanup(func() { _ = ss.files.Close() })
	a, err := newUIApp(p, ss, st)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// waitForReview waits for a review in the background to finish.
func waitForReview(t *testing.T, a *uiApp) ui.ReviewState {
	t.Helper()
	for range 3000 {
		if r := a.ScanState().Review; r != nil && !r.Running {
			return *r
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the review didn't finish")
	return ui.ReviewState{}
}

func TestTheLLMReviewIsSetUpFromTheDashboard(t *testing.T) {
	home := demoCopy(t)
	a := keyApp(t, home, true)

	err := a.SaveLLM(ui.LLMForm{BaseURL: " https://llm.example.com/v1/ ", Model: "m-2", KeyEnv: "JARX_LLM_KEY", Parallel: "3"})

	if err != nil {
		t.Fatalf("SaveLLM = %v", err)
	}
	l := a.Data().LLM
	if !l.On || l.BaseURL.String() != "https://llm.example.com/v1" || l.Model.String() != "m-2" || l.Parallel != 3 || !l.KeySet || len(l.Artifacts) == 0 {
		t.Errorf("LLM data = %+v, want it on with the saved settings and the checklist", l)
	}
	if got := runIn("", "setup", "--home", home); !strings.Contains(got.stdout, "m-2") {
		t.Errorf("jarx setup doesn't show the saved model: %q", got.stdout)
	}
}

func TestLLMSettingsThatWontDoAreRefused(t *testing.T) {
	a := keyApp(t, demoCopy(t), true)
	good := ui.LLMForm{BaseURL: "https://llm.example.com/v1", Model: "m", KeyEnv: "JARX_LLM_KEY", Parallel: "2"}
	for name, tc := range map[string]struct {
		edit func(*ui.LLMForm)
		want error
	}{
		"no url":         {func(f *ui.LLMForm) { f.BaseURL = "" }, ui.ErrLLMURL},
		"a query":        {func(f *ui.LLMForm) { f.BaseURL = "https://llm.example.com/v1?x=1" }, ui.ErrLLMURL},
		"a key as model": {func(f *ui.LLMForm) { f.Model = "sk-abcdefabcdefabcdefabcdef" }, ui.ErrLooksLikeKey},
		"a spaced model": {func(f *ui.LLMForm) { f.Model = "m 1" }, ui.ErrLLMModel},
		"a bad var":      {func(f *ui.LLMForm) { f.KeyEnv = "1KEY" }, ui.ErrLLMVar},
		"too parallel":   {func(f *ui.LLMForm) { f.Parallel = "99" }, ui.ErrLLMParallel},
	} {
		f := good
		tc.edit(&f)

		if err := a.SaveLLM(f); !errors.Is(err, tc.want) {
			t.Errorf("%s: SaveLLM = %v, want %v", name, err, tc.want)
		}
	}
	if a.Data().LLM.On {
		t.Error("a refused form turned the review on")
	}
}

func TestTheLLMReviewIsTurnedOffFromTheDashboard(t *testing.T) {
	a := keyApp(t, llmDemo(t, "https://llm.example.com/v1"), true)

	if err := a.LLMOff(); err != nil || a.Data().LLM.On {
		t.Errorf("LLMOff = %v, on %v; want it off", err, a.Data().LLM.On)
	}
}

func TestTestConnectionSaysHowItWent(t *testing.T) {
	ok := &reviewer{}
	rejected := &reviewer{status: http.StatusUnauthorized}
	for name, tc := range map[string]struct {
		base    string
		withKey bool
		want    error
	}{
		"connected": {ok.serve(t), true, nil},
		"no key":    {ok.serve(t), false, ui.ErrKeyNotSet},
		"rejected":  {rejected.serve(t), true, ui.ErrKeyRejected},
		"no one":    {"http://127.0.0.1:1/v1", true, ui.ErrUnreachable},
	} {
		a := keyApp(t, llmDemo(t, tc.base), tc.withKey)

		if err := a.TestLLM(); !errors.Is(err, tc.want) {
			t.Errorf("%s: TestLLM = %v, want %v", name, err, tc.want)
		}
	}
}

func TestReviewSendsOnlyTheCheckedArtifacts(t *testing.T) {
	f := &reviewer{}
	a := keyApp(t, llmDemo(t, f.serve(t)), true)
	skill := firstSkill(a.Data())

	if err := a.Review([]string{llm.KeyOf(skill), "not-an-artifact"}); err != nil {
		t.Fatal(err)
	}
	r := waitForReview(t, a)

	if f.count() != 1 || r.Total != 1 || r.Done != 1 || r.Finished != 1 || r.Stopped != "" {
		t.Errorf("sent %d, review %+v; want just the one checked artifact, done", f.count(), r)
	}
	if !hasRule(a.Data(), llm.RuleHigh().ID) {
		t.Error("the review's finding doesn't show in the dashboard")
	}
	if st := stateOf(a.Data(), llm.KeyOf(skill)); st != llm.StateCached {
		t.Errorf("the reviewed artifact is %q, want cached", st)
	}
}

// firstSkill is the checklist's first skill.
func firstSkill(d ui.Data) llm.Artifact {
	for _, art := range d.LLM.Artifacts {
		if art.Kind == llm.KindSkill {
			return art
		}
	}
	return llm.Artifact{}
}

// stateOf is the checklist's state for the artifact with this key.
func stateOf(d ui.Data, key string) llm.State {
	for i, art := range d.LLM.Artifacts {
		if llm.KeyOf(art) == key {
			return d.LLM.States[i]
		}
	}
	return ""
}

func TestAReviewThatCantStartSaysWhy(t *testing.T) {
	f := &reviewer{}
	noKey := keyApp(t, llmDemo(t, f.serve(t)), false)
	off := keyApp(t, demoCopy(t), true)
	on := keyApp(t, llmDemo(t, f.serve(t)), true)
	key := llm.KeyOf(on.Data().LLM.Artifacts[0])

	for name, tc := range map[string]struct {
		err, want error
	}{
		"no key":  {noKey.Review([]string{key}), ui.ErrKeyNotSet},
		"off":     {off.Review([]string{key}), ui.ErrLLMOff},
		"nothing": {on.Review([]string{"nope"}), ui.ErrNothingToSend},
	} {
		if !errors.Is(tc.err, tc.want) {
			t.Errorf("%s: Review = %v, want %v", name, tc.err, tc.want)
		}
	}
	if f.count() != 0 {
		t.Errorf("sent %d requests, want none", f.count())
	}
}

func TestAReviewTheEndpointRefusesStopsAndSaysWhy(t *testing.T) {
	f := &reviewer{status: http.StatusUnauthorized}
	a := keyApp(t, llmDemo(t, f.serve(t)), true)

	if err := a.Review([]string{llm.KeyOf(a.Data().LLM.Artifacts[0])}); err != nil {
		t.Fatal(err)
	}

	if r := waitForReview(t, a); r.Stopped != "review-rejected" {
		t.Errorf("review %+v, want it stopped with review-rejected", r)
	}
}

func hasRule(d ui.Data, id string) bool {
	for _, f := range d.Scan.Findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestASkipShowsAndLastsUntilUndone(t *testing.T) {
	f := &reviewer{}
	demo := llmDemo(t, f.serve(t))
	a := keyApp(t, demo, true)
	skill := firstSkill(a.Data())
	sendBefore := a.Data().LLM.Plan.Send

	if err := a.Skip([]string{llm.KeyOf(skill)}, true); err != nil {
		t.Fatal(err)
	}

	again := keyApp(t, demo, true) // a new jarx ui reads the skip list too
	for _, d := range []ui.Data{a.Data(), again.Data()} {
		if stateOf(d, llm.KeyOf(skill)) != llm.StateSkipped || d.LLM.Skipped != 1 || d.LLM.Plan.Send != sendBefore-1 {
			t.Errorf("state %q, skipped %d, send %d; want skipped, 1, %d", stateOf(d, llm.KeyOf(skill)), d.LLM.Skipped, d.LLM.Plan.Send, sendBefore-1)
		}
	}
	if err := a.Skip([]string{llm.KeyOf(skill)}, false); err != nil {
		t.Fatal(err)
	}
	if stateOf(a.Data(), llm.KeyOf(skill)) == llm.StateSkipped || a.Data().LLM.Skipped != 0 {
		t.Error("unskipping didn't bring it back")
	}
}

func TestASkippedArtifactsOldFindingsDontShow(t *testing.T) {
	f := &reviewer{}
	demo := llmDemo(t, f.serve(t))
	if got := withKey().ask("y\n", "scan", "--llm", "--home", demo); got.code != 0 {
		t.Fatalf("scan --llm = %d", got.code)
	}
	a := keyApp(t, demo, true)
	if !hasRule(a.Data(), llm.RuleHigh().ID) {
		t.Fatal("no cached finding to start with")
	}

	if err := a.Skip([]string{llm.KeyOf(firstSkill(a.Data()))}, true); err != nil {
		t.Fatal(err)
	}

	if hasRule(a.Data(), llm.RuleHigh().ID) {
		t.Error("a skipped artifact's cached finding still shows")
	}
}

func TestAReviewNeverSendsASkippedArtifact(t *testing.T) {
	f := &reviewer{}
	a := keyApp(t, llmDemo(t, f.serve(t)), true)
	key := llm.KeyOf(firstSkill(a.Data()))
	if err := a.Skip([]string{key}, true); err != nil {
		t.Fatal(err)
	}

	if err := a.Review([]string{key}); !errors.Is(err, ui.ErrNothingToSend) {
		t.Errorf("Review(a skipped one) = %v, want ErrNothingToSend", err)
	}
	if f.count() != 0 {
		t.Errorf("sent %d requests, want none", f.count())
	}
}
