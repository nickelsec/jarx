package cli

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/jarxdir"
	"github.com/nickelsec/jarx/internal/llm"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/netguard"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
	"github.com/nickelsec/jarx/internal/report"
)

// errNoLLM means scan --llm refused before scanning; the reason is printed.
var errNoLLM = errors.New("llm review can't run")

// llmRun is jarx scan --llm's review, checked before the scan starts.
type llmRun struct {
	p      *report.Printer
	s      *redact.Scrubber
	st     streams
	ep     llm.Endpoint
	keyEnv string
}

// prepareLLM checks, before anything is scanned, that the review is set up
// and its key is set in this terminal, and says what to do when it isn't.
func prepareLLM(p *report.Printer, s *redact.Scrubber, cfg jarxdir.Config, st streams) (*llmRun, error) {
	if cfg.LLM == nil {
		p.Err.Printf("jarx: llm review isn't set up. run jarx setup llm first\n")
		return nil, errNoLLM
	}
	name := cfg.LLM.KeyEnv
	key, ok := llm.KeyFrom(st.lookupKey, name)
	if !ok {
		ps, sh := keyCommands(name)
		p.Err.Printf("jarx: %s isn't set in this terminal. set it without it landing in shell history, then run jarx scan --llm again:\n", scrubbed(s, name))
		p.Err.Printf("  powershell  %s\n  bash, zsh   %s\n", scrubbed(s, ps), scrubbed(s, sh))
		return nil, errNoLLM
	}
	return &llmRun{p: p, s: s, st: st, ep: llm.Endpoint{BaseURL: cfg.LLM.BaseURL, Model: cfg.LLM.Model, Key: key}, keyEnv: name}, nil
}

// kindWords are each artifact kind's words, in the order the preview lists
// them.
//
//nolint:gochecknoglobals // fixed table, read only
var kindWords = []struct {
	kind      llm.Kind
	one, many string
}{
	{llm.KindTool, "tool", "tools"},
	{llm.KindSkill, "skill", "skills"},
	{llm.KindInstructions, "instruction file", "instruction files"},
	{llm.KindHook, "hook", "hooks"},
}

// run shows what the review would send and asks first. It returns the
// review's findings and the exit code; stop means ctrl+c, so the scan
// stops with that code instead of printing the rest.
func (r *llmRun) run(env platform.Env, projects []model.Project) ([]finding.Finding, int, bool) {
	arts := llm.Collect(r.s, projects)
	cache := llm.LoadCache(env)
	plan := llm.Plan(r.ep, arts, cache)
	switch {
	case len(arts) == 0:
		r.p.Say(r.text("llm review: nothing to review"))
		r.p.Blank()
		return nil, exitOK, false
	case plan.Send == 0:
		// Nothing leaves the machine, so there's nothing to ask about.
		r.p.Say(r.text("llm review: all " + strconv.Itoa(plan.Cached) + " artifacts are cached, nothing sent"))
		r.p.Blank()
		res, _ := llm.Review(context.Background(), netguard.NewLLM(), r.ep, r.s, arts, cache)
		return res.Findings, exitOK, false
	}
	r.preview(plan)
	r.p.Blank()
	r.p.YesNo(r.text("send "+plural(plan.Send, "artifact", "artifacts")+" to "+plan.Host+"?"), false, nil)
	a, done := newAsker(r.p, r.s, r.st)
	defer done()
	yes, ok := a.yesNo(false)
	switch {
	case !ok && a.interrupted:
		r.p.Blank()
		r.p.Say(r.text("cancelled, nothing sent"))
		return nil, exitInterrupted, true
	case !ok || !yes:
		r.p.Say(r.text("not sent"))
		r.p.Blank()
		return nil, exitOK, false
	}
	var res llm.Result
	var err error
	a.whileCatching(0, func(ctx context.Context) {
		res, err = llm.Review(ctx, netguard.NewLLM(), r.ep, r.s, arts, cache)
	})
	saveErr := cache.Save(env)
	if a.interrupted {
		r.p.Blank()
		r.p.Say(r.text("cancelled. the review stopped, and nothing more was sent"))
		return nil, exitInterrupted, true
	}
	code := r.report(res, err, saveErr)
	return res.Findings, code, false
}

func (r *llmRun) text(v string) redact.Text { return scrubbed(r.s, v) }

func (r *llmRun) preview(plan llm.Preview) {
	v := report.LLMPreviewView{
		Send: plan.Send, Tokens: plan.Tokens, Cached: plan.Cached,
		Host: r.text(plan.Host), Model: r.text(r.ep.Model), KeyEnv: r.text(r.keyEnv),
	}
	for _, k := range kindWords {
		v.Kinds = append(v.Kinds, report.Count{N: plan.ByKind[k.kind], One: k.one, Many: k.many})
	}
	r.p.LLMPreview(v)
}

// report says how the review went, and returns 1 when it stopped early.
func (r *llmRun) report(res llm.Result, err, saveErr error) int {
	parts := []string{"reviewed " + strconv.Itoa(res.Sent+res.Cached)}
	if res.Cached > 0 {
		parts = append(parts, strconv.Itoa(res.Cached)+" from the cache")
	}
	if res.Failed > 0 {
		parts = append(parts, strconv.Itoa(res.Failed)+" failed after a retry, see the INFO findings")
	}
	if res.Dropped > 0 {
		parts = append(parts, plural(res.Dropped, "finding", "findings")+" dropped, its quote wasn't in the artifact")
	}
	r.p.Say(r.text(strings.Join(parts, r.p.Sep())))
	code := exitOK
	if err != nil {
		r.p.Say(r.text("llm review stopped: " + err.Error()))
		code = exitError
	}
	if saveErr != nil {
		r.p.Hint(r.text("couldn't save the llm cache: " + saveErr.Error()))
	}
	r.p.Blank()
	return code
}
