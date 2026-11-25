package ui

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/llm"
)

func TestSettingsEditsTheLLMReview(t *testing.T) {
	_, body, _ := get(t, newFixture(t).data(), "/settings")

	if !order(body, `<form class="llm-form" method="post" action="/settings/llm">`, `<input type="hidden" name="action" value="save">`,
		`name="url"`, `value="https://llm.example.com/v1"`, `name="model"`, `value="m-1"`, `name="keyenv"`, `value="JARX_LLM_KEY"`, `name="parallel"`, `value="4"`, "Save") {
		t.Errorf("settings has no form to change the LLM review:\n%s", body)
	}
	if !order(body, `<input type="hidden" name="action" value="test">`, "Test connection") {
		t.Error("settings has no Test connection")
	}
	if !order(body, `data-open="llm-off"`, "Turn off", `<dialog class="modal confirm" id="llm-off"`, `<input type="hidden" name="action" value="off">`) {
		t.Error("Turn off doesn't ask first")
	}
	if strings.Contains(body, "for now") || strings.Count(body, "<section") != strings.Count(body, "</section>") {
		t.Error("settings still says to use the terminal, or its sections don't close")
	}
}

func TestSettingsSetsUpAnLLMReviewThatsOff(t *testing.T) {
	d := newFixture(t).data()
	d.LLM = LLM{}

	_, body, _ := get(t, d, "/settings")

	if !order(body, `<form class="llm-form" method="post" action="/settings/llm">`, `name="url"`, `placeholder="https://`, "Turn on") || strings.Contains(body, "Turn off") {
		t.Error("settings can't turn on an LLM review that's off")
	}
}

func TestLLMSettingsSayHowTheyWent(t *testing.T) {
	for name, tc := range map[string]struct {
		action string
		err    error
		want   string
	}{
		"saved":         {"save", nil, "llm-saved"},
		"bad url":       {"save", ErrLLMURL, "llm-url"},
		"bad model":     {"save", ErrLLMModel, "llm-model"},
		"bad var":       {"save", ErrLLMVar, "llm-var"},
		"bad parallel":  {"save", ErrLLMParallel, "llm-parallel"},
		"a key":         {"save", ErrLooksLikeKey, "llm-key"},
		"connected":     {"test", nil, "llm-ok"},
		"no key here":   {"test", ErrKeyNotSet, "llm-nokey"},
		"key rejected":  {"test", ErrKeyRejected, "llm-rejected"},
		"unreachable":   {"test", ErrUnreachable, "llm-unreachable"},
		"test, other":   {"test", errors.New("odd"), "llm-failed"},
		"off":           {"off", nil, "llm-off"},
		"no such thing": {"dance", nil, "llm-failed"},
	} {
		a := &fakeApp{d: newFixture(t).data(), llmErr: tc.err}

		resp := post(t, a, "/settings/llm", url.Values{"action": {tc.action}, "url": {"https://x.example/v1"}, "model": {"m"}, "keyenv": {"K"}, "parallel": {"2"}})

		if resp.StatusCode != http.StatusSeeOther || resp.Location != "/settings?msg="+tc.want {
			t.Errorf("%s: %d to %q, want msg=%s", name, resp.StatusCode, resp.Location, tc.want)
		}
	}
	a := &fakeApp{d: newFixture(t).data()}
	post(t, a, "/settings/llm", url.Values{"action": {"save"}, "url": {" https://x.example/v1 "}, "model": {"m"}, "keyenv": {"K"}, "parallel": {"2"}})
	if a.llm != (LLMForm{BaseURL: " https://x.example/v1 ", Model: "m", KeyEnv: "K", Parallel: "2"}) {
		t.Errorf("saved %+v, want the form as typed (the app checks it)", a.llm)
	}
}

func TestTheLLMPageAsksBeforeSending(t *testing.T) {
	_, body, _ := get(t, newFixture(t).data(), "/llm")

	if !order(body, `<form id="review" method="post" action="/llm/review"`, `<button type="button" class="btn primary" data-open="review-confirm"`, "Review checked", `data-tokens="`) {
		t.Errorf("the LLM page has no Review checked that asks first:\n%s", body)
	}
	if !order(body, `<dialog class="modal confirm" id="review-confirm"`, "Send to llm.example.com?", `data-send-count`, `data-send-tokens`, "Cancel", `<button type="submit" form="review" class="btn primary">Send</button>`) {
		t.Error("the confirmation doesn't say where it sends, or can't send")
	}
}

func TestAReviewStartsAndGoesBack(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"started": {nil, "/llm"},
		"busy":    {ErrBusy, "/llm?msg=review-busy"},
		"no key":  {ErrKeyNotSet, "/llm?msg=review-nokey"},
		"nothing": {ErrNothingToSend, "/llm?msg=review-none"},
		"off":     {ErrLLMOff, "/llm?msg=review-off"},
		"other":   {errors.New("odd"), "/llm?msg=review-failed"},
	} {
		a := &fakeApp{d: newFixture(t).data(), reviewErr: tc.err}

		resp := post(t, a, "/llm/review", url.Values{"a": {"k1", "k2"}})

		if resp.Location != tc.want {
			t.Errorf("%s: went to %q, want %q", name, resp.Location, tc.want)
		}
		if name == "started" && !slices.Equal(a.reviewed, []string{"k1", "k2"}) {
			t.Errorf("started: reviewed %q, want the checked keys", a.reviewed)
		}
	}
}

func TestTheLLMPageShowsAReviewRunning(t *testing.T) {
	a := &fakeApp{d: newFixture(t).data(), state: ScanState{Review: &ReviewState{Running: true, Done: 3, Total: 7, Waiting: 1}}}

	body := getApp(t, a, "/llm")

	if !order(body, `<span hidden data-review="running"></span>`, `data-review-progress`, "3 of 7", "1 waiting on a rate limit") {
		t.Errorf("the LLM page doesn't show the review running:\n%s", body)
	}
	if !strings.Contains(body, `<button type="button" class="btn primary busy" disabled>`) {
		t.Error("Review checked doesn't show the review running")
	}
}

func TestASkippedArtifactSaysSoAndIsntChecked(t *testing.T) {
	d := newFixture(t).data()
	d.LLM.States[1] = llm.StateSkipped
	d.LLM.Skipped = 1

	_, body, _ := get(t, d, "/llm")

	_, row, _ := strings.Cut(body, "save_note of notes")
	row, _, _ = strings.Cut(row, "</label>")
	if !strings.Contains(row, `<span class="state st-skipped">skipped</span>`) || strings.Contains(row, "not reviewed") {
		t.Errorf("the skipped row doesn't say so:\n%s", row)
	}
	if !strings.Contains(body, `value="`+llm.KeyOf(d.LLM.Artifacts[1])+`" data-tokens="0" aria-label`) {
		t.Error("a skipped artifact is checked, or costs tokens")
	}
	if !order(body, `<span class="tile-label">Skipped</span>`, `<span class="tile-n">1</span>`) {
		t.Error("the tiles don't count what's skipped")
	}
}

func TestTheChecklistCanSkipUnskipAndRerunFailed(t *testing.T) {
	d := newFixture(t).data()
	d.LLM.Skipped = 1

	_, body, _ := get(t, d, "/llm")

	for _, want := range []string{
		`<button type="button" class="btn" data-rerun>Rerun failed</button>`,
		`<button type="submit" form="review" formaction="/llm/skip" name="action" value="skip" class="btn ghost">Skip checked</button>`,
		`<button type="submit" form="review" formaction="/llm/skip" name="action" value="unskip" class="btn ghost">Unskip checked</button>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the checklist lacks %q", want)
		}
	}
	key0, key1 := llm.KeyOf(d.LLM.Artifacts[0]), llm.KeyOf(d.LLM.Artifacts[1])
	if !strings.Contains(body, `data-arts="`+key0+`:`) || !strings.Contains(body, ":new "+key1+":") || !strings.Contains(body, ":failed\"") {
		t.Errorf("the page doesn't carry every artifact for the picks:\n%s", body)
	}
}

func TestSkipAndUnskipSayHowTheyWent(t *testing.T) {
	for name, tc := range map[string]struct {
		action string
		err    error
		on     bool
		want   string
	}{
		"skip":   {"skip", nil, true, "/llm?msg=skipped"},
		"unskip": {"unskip", nil, false, "/llm?msg=unskipped"},
		"failed": {"skip", errors.New("disk full"), true, "/llm?msg=skip-failed"},
	} {
		a := &fakeApp{d: newFixture(t).data(), skipErr: tc.err}

		resp := post(t, a, "/llm/skip", url.Values{"action": {tc.action}, "a": {"k1"}})

		if resp.Location != tc.want || !slices.Equal(a.skipped, []string{"k1"}) || a.skipOn != tc.on {
			t.Errorf("%s: went to %q, skipped %q (%v); want %q", name, resp.Location, a.skipped, a.skipOn, tc.want)
		}
	}
}
