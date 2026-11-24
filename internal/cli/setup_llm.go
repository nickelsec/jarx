package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/nickelsec/jarx/internal/catalog"
	"github.com/nickelsec/jarx/internal/jarxdir"
	"github.com/nickelsec/jarx/internal/llm"
	"github.com/nickelsec/jarx/internal/netguard"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
	"github.com/nickelsec/jarx/internal/report"
)

// defaultKeyEnv is the var name setup offers. A name only jarx uses is less
// likely to already sit in a shell profile, where the agents can read it.
const defaultKeyEnv = "JARX_LLM_KEY"

// Limits on answers.
const (
	maxAnswer  = 4096
	maxModel   = 200
	maxVarName = 128
	pingWait   = 20 * time.Second
	llmFlagN   = 3 // --url, --model and --key-env
)

var varName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// llmFlags are the one-line version's flags.
type llmFlags struct {
	home, url, model, keyEnv string
	set                      int // how many of url, model and key-env were given
	off                      bool
}

// runSetupLLM runs jarx setup llm: off, the one-line version with all three
// flags, or the questions when there's a terminal.
func runSetupLLM(p *report.Printer, plain *redact.Scrubber, args []string, home string, st streams) int {
	f, code, ok := parseSetupLLM(p, plain, args)
	if !ok {
		return code
	}
	if f.home != "" {
		home = f.home
	}
	if !f.off && f.set == 0 && !st.interactive {
		p.Err.Printf("jarx setup llm asks one question at a time, so it needs a terminal.\n" +
			"for scripts, give all three as flags:\n" +
			"  jarx setup llm --url https://llm.example.com/v1 --model <model> --key-env " + defaultKeyEnv + "\n")
		return exitUsage
	}
	env, scrub, cfg, err := openLLMSetup(home)
	if err != nil {
		p.Error(err)
		return exitError
	}
	switch {
	case f.off:
		return llmOff(p, scrub, env, cfg)
	case f.set > 0:
		return llmFromFlags(p, scrub, env, cfg, f, st.lookupKey)
	default:
		return askLLM(p, scrub, env, cfg, st)
	}
}

// askLLM asks the setup questions, catching ctrl+c while it does.
func askLLM(p *report.Printer, scrub *redact.Scrubber, env platform.Env, cfg jarxdir.Config, st streams) int {
	a, done := newAsker(p, scrub, st)
	defer done()
	return a.setup(env, cfg)
}

// newAsker starts reading answers from st's input and catching ctrl+c.
// Call done when the questions are over, so ctrl+c works the usual way
// again.
func newAsker(p *report.Printer, scrub *redact.Scrubber, st streams) (*asker, func()) {
	notify := st.interrupt
	if notify == nil {
		notify = catchInterrupt
	}
	sig, stop := notify()
	a := &asker{p: p, s: scrub, r: bufio.NewReader(st.in), sig: sig, lines: make(chan readLine), done: make(chan struct{}), lookup: st.lookupKey}
	go a.read()
	return a, func() {
		close(a.done)
		stop()
	}
}

// openLLMSetup builds the env and loads jarx's config. Setup only checks
// whether an answer looks like a key, so its scrubber has no fingerprint
// key: a refused answer must not create the state dir.
func openLLMSetup(home string) (platform.Env, *redact.Scrubber, jarxdir.Config, error) {
	env, files, _, err := openEnv(home)
	if err != nil {
		return platform.Env{}, nil, jarxdir.Config{}, err
	}
	_ = files.Close() // setup llm reads no files beyond jarx's own config
	scrub, err := detector()
	if err != nil {
		return platform.Env{}, nil, jarxdir.Config{}, err
	}
	cfg, err := jarxdir.LoadConfig(env)
	if err != nil {
		return platform.Env{}, nil, jarxdir.Config{}, err //nolint:wrapcheck // jarxdir errors already say what failed
	}
	return env, scrub, cfg, nil
}

// detector is a scrubber with the secret patterns and no fingerprint key.
func detector() (*redact.Scrubber, error) {
	patterns, err := catalog.Secrets()
	if err != nil {
		return nil, err //nolint:wrapcheck // catalog errors already say what failed
	}
	return redact.New(patterns, nil) //nolint:wrapcheck // redact errors already say what failed
}

func parseSetupLLM(p *report.Printer, plain *redact.Scrubber, args []string) (llmFlags, int, bool) {
	var f llmFlags
	if len(args) > 0 && args[0] == "off" {
		f.off = true
		args = args[1:]
	}
	fs := newFlagSet("setup llm")
	fs.StringVar(&f.home, "home", "", "")
	fs.StringVar(&f.url, "url", "", "")
	fs.StringVar(&f.model, "model", "", "")
	fs.StringVar(&f.keyEnv, "key-env", "", "")
	if code, ok := parse(p, plain, fs, args, setupHelp); !ok {
		return f, code, false
	}
	if emptyHome(fs, f.home) {
		return f, usageError(p, setupHelp, scrubbed(plain, "--home needs a directory")), false
	}
	rest := fs.Args()
	if !f.off && len(rest) == 1 && rest[0] == "off" {
		f.off, rest = true, nil
	}
	fs.Visit(func(fl *flag.Flag) {
		if fl.Name != "home" {
			f.set++
		}
	})
	if problem := llmUsageProblem(f, rest); problem != "" {
		return f, usageError(p, setupHelp, scrubbed(plain, problem)), false
	}
	return f, exitOK, true
}

// llmUsageProblem says what's wrong with how setup llm was called, or "".
func llmUsageProblem(f llmFlags, rest []string) string {
	switch {
	case len(rest) > 0:
		return "want: setup llm, setup llm off, or setup llm with --url, --model and --key-env"
	case f.off && f.set > 0:
		return "setup llm off takes no other flags"
	case f.set > 0 && f.set < llmFlagN:
		return "the one-line version needs all three: --url, --model and --key-env"
	}
	return ""
}

func llmFromFlags(p *report.Printer, s *redact.Scrubber, env platform.Env, cfg jarxdir.Config, f llmFlags, lookup keyLookup) int {
	base, err := checkBaseURL(s, f.url)
	if err != nil {
		p.Error(fmt.Errorf("--url: %w", err))
		return exitError
	}
	model, err := checkModel(s, f.model)
	if err != nil {
		p.Error(fmt.Errorf("--model: %w", err))
		return exitError
	}
	keyEnv, err := checkVarName(s, f.keyEnv)
	if err != nil {
		p.Error(fmt.Errorf("--key-env: %w", err))
		return exitError
	}
	cfg.LLM = &jarxdir.LLM{BaseURL: base, Model: model, KeyEnv: keyEnv}
	if err := save(env, cfg); err != nil {
		p.Error(err)
		return exitError
	}
	p.LLMSummary(llmView(s, lookup, *cfg.LLM))
	p.Blank()
	p.Say(scrubbed(s, "saved to "+homeShort(env, configPath(env))))
	return exitOK
}

func llmOff(p *report.Printer, s *redact.Scrubber, env platform.Env, cfg jarxdir.Config) int {
	if cfg.LLM == nil {
		p.Say(scrubbed(s, "llm review is already off"))
		return exitOK
	}
	name := cfg.LLM.KeyEnv
	cfg.LLM = nil
	if err := save(env, cfg); err != nil {
		p.Error(err)
		return exitError
	}
	p.Say(scrubbed(s, "llm review is off. removed the endpoint, model and key var name"))
	p.Say(scrubbed(s, "your "+name+" env var is untouched"))
	return exitOK
}

// llmView is the LLM settings as report shows them, with whether the key's
// var is set here. It never holds the key.
func llmView(s *redact.Scrubber, lookup keyLookup, c jarxdir.LLM) report.LLMView {
	_, set := llm.KeyFrom(lookup, c.KeyEnv)
	return report.LLMView{
		BaseURL: scrubbed(s, c.BaseURL),
		Model:   scrubbed(s, c.Model),
		KeyEnv:  scrubbed(s, c.KeyEnv),
		KeySet:  set,
	}
}

// errLooksLikeKey is for an answer that looks like a key, which jarx won't
// save anywhere.
var errLooksLikeKey = errors.New("that looks like a key. jarx never stores keys, so it won't save one here")

// looksLikeKey is a match for the secret patterns, or an "sk-" key, which
// several providers use and none documents as a pattern.
func looksLikeKey(s *redact.Scrubber, v string) bool {
	if _, finds := s.Scrub(v); len(finds) > 0 {
		return true
	}
	return strings.HasPrefix(strings.ToLower(v), "sk-")
}

// checkBaseURL checks a base URL with netguard's rules and the key check,
// and drops a trailing slash.
func checkBaseURL(s *redact.Scrubber, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("a base url is needed")
	}
	if err := netguard.CheckURL(raw); err != nil {
		if errors.Is(err, netguard.ErrInsecure) {
			_, why, _ := strings.Cut(err.Error(), ": ")
			return "", errors.New(why)
		}
		return "", err //nolint:wrapcheck // netguard's text says what's wrong
	}
	if looksLikeKey(s, raw) {
		return "", errLooksLikeKey
	}
	if u, err := url.Parse(raw); err == nil {
		for seg := range strings.SplitSeq(u.Path, "/") {
			if looksLikeKey(s, seg) {
				return "", errLooksLikeKey
			}
		}
	}
	return strings.TrimRight(raw, "/"), nil
}

func checkModel(s *redact.Scrubber, raw string) (string, error) {
	m := strings.TrimSpace(raw)
	switch {
	case m == "":
		return "", errors.New("a model is needed")
	case looksLikeKey(s, m):
		return "", errLooksLikeKey
	case strings.ContainsFunc(m, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }):
		return "", errors.New("a model name has no spaces")
	case len(m) > maxModel:
		return "", errors.New("that's too long for a model name")
	}
	return m, nil
}

func checkVarName(s *redact.Scrubber, raw string) (string, error) {
	n := strings.TrimSpace(raw)
	switch {
	case looksLikeKey(s, n):
		return "", errLooksLikeKey
	case !varName.MatchString(n) || len(n) > maxVarName:
		return "", errors.New("an env var name is letters, digits and _, and doesn't start with a digit")
	}
	return n, nil
}

// homeShort shows path from ~ when it's inside the home dir.
func homeShort(env platform.Env, path string) string {
	if rel, err := filepath.Rel(env.Home, path); err == nil && filepath.IsLocal(rel) {
		return "~" + string(filepath.Separator) + rel
	}
	return path
}

// asker asks the setup questions and reads the answers.
type asker struct {
	p     *report.Printer
	s     *redact.Scrubber
	r     *bufio.Reader
	sig   <-chan os.Signal // ctrl+c
	lines chan readLine    // unbuffered, so nothing is read ahead of a question
	done  chan struct{}    // closed when setup returns

	lookup keyLookup // the terminal's env, for the key

	interrupted bool // ctrl+c, not the end of input, stopped it
	saved       bool
}

// readLine is one line of input, or the end of it.
type readLine struct {
	text string
	eof  bool
}

// exitInterrupted is the usual exit code after ctrl+c (128 + SIGINT).
const exitInterrupted = 130

// read sends each line of input to lines until the end of input or until
// setup returns.
func (a *asker) read() {
	for {
		l, err := a.r.ReadString('\n')
		next := readLine{text: l, eof: err != nil && l == ""}
		select {
		case a.lines <- next:
		case <-a.done:
			return
		}
		if next.eof {
			return
		}
	}
}

func (a *asker) text(v string) redact.Text { return scrubbed(a.s, v) }

func (a *asker) texts(vs ...string) []redact.Text {
	out := make([]redact.Text, len(vs))
	for i, v := range vs {
		out[i] = a.text(v)
	}
	return out
}

// answer reads one answer, or def for an empty one. ok is false at the end
// of input.
func (a *asker) answer(def string) (string, bool) {
	a.p.Prompt()
	var l string
	select {
	case next := <-a.lines:
		if next.eof {
			return "", false
		}
		l = next.text
	case <-a.sig:
		a.interrupted = true
		return "", false
	}
	l = strings.TrimSpace(l)
	if len(l) > maxAnswer {
		l = l[:maxAnswer]
	}
	if l == "" {
		l = def
	}
	return l, true
}

// until asks again until check takes the answer.
func (a *asker) until(def string, check func(string) (string, error)) (string, bool) {
	for {
		raw, ok := a.answer(def)
		if !ok {
			return "", false
		}
		v, err := check(raw)
		if err == nil {
			return v, true
		}
		a.p.AnswerNote(a.text(err.Error()))
	}
}

// yesNo asks until it gets y, yes, n, no or Enter. At the end of input it
// returns ok false.
func (a *asker) yesNo(def bool) (bool, bool) {
	for {
		raw, ok := a.answer("")
		if !ok {
			return false, false
		}
		switch strings.ToLower(raw) {
		case "":
			return def, true
		case "y", "yes":
			return true, true
		case "n", "no":
			return false, true
		}
		a.p.AnswerNote(a.text("answer y or n"))
	}
}

// quit says what was and wasn't saved when ctrl+c or the end of input
// stops setup.
func (a *asker) quit() int {
	a.p.Blank()
	if a.saved {
		a.p.Say(a.text("cancelled. the settings are saved"))
	} else {
		a.p.Say(a.text("cancelled, nothing saved"))
	}
	if a.interrupted {
		return exitInterrupted
	}
	return exitError
}

// The questions setup asks, in order.
const (
	stepURL = iota + 1
	stepModel
	stepKeyEnv
	llmSteps = stepKeyEnv
)

// setup asks for the base URL, the model and the key's var name, shows a
// summary, saves on a yes, then offers the connection test.
func (a *asker) setup(env platform.Env, cfg jarxdir.Config) int {
	var cur jarxdir.LLM
	if cfg.LLM != nil {
		cur = *cfg.LLM
	}
	if cur.KeyEnv == "" {
		cur.KeyEnv = defaultKeyEnv
	}
	a.p.Intro(a.text("llm review setup"), a.texts(
		"jarx sends one masked artifact at a time to an OpenAI-compatible endpoint",
		"the key stays in an env var you set. jarx never stores it",
		"enter keeps the default"+a.p.Sep()+"ctrl+c quits without saving",
	))
	a.p.Blank()
	next, ok := a.ask(cur)
	if !ok {
		return a.quit()
	}
	cfg.LLM = &next
	saved, code := a.confirmSave(env, cfg)
	if !saved {
		return code
	}
	key, keySet := llm.KeyFrom(a.lookup, next.KeyEnv)
	if !keySet {
		a.p.Hint(a.text("set " + next.KeyEnv + ", then run jarx setup llm again to test the connection"))
		return exitOK
	}
	return a.offerTest(next, key)
}

// ask asks the three questions, with cur's values as the defaults. ok is
// false at the end of input.
func (a *asker) ask(cur jarxdir.LLM) (jarxdir.LLM, bool) {
	a.p.Question(stepURL, llmSteps, a.text("base url"), a.text(cur.BaseURL), a.texts(
		"an OpenAI-compatible endpoint: https, or http on loopback only",
		"like https://api.openai.com/v1 or http://127.0.0.1:11434/v1",
	))
	base, ok := a.until(cur.BaseURL, func(v string) (string, error) { return checkBaseURL(a.s, v) })
	if !ok {
		return jarxdir.LLM{}, false
	}
	u, _ := url.Parse(base) // checkBaseURL parsed it already
	a.p.AnswerOK(a.text(strings.ToLower(u.Scheme)+a.p.Sep()+u.Host), redact.Text{})
	a.p.Blank()

	a.p.Question(stepModel, llmSteps, a.text("model"), a.text(cur.Model), a.texts("the model name your endpoint expects"))
	model, ok := a.until(cur.Model, func(v string) (string, error) { return checkModel(a.s, v) })
	if !ok {
		return jarxdir.LLM{}, false
	}
	a.p.Blank()

	a.p.Question(stepKeyEnv, llmSteps, a.text("key env var"), a.text(cur.KeyEnv), a.texts(
		"the name of the env var that holds the key, read only when jarx sends",
		"set it only in the terminal you run jarx from. a key in your shell profile is in every agent's env too, so the agents can read it",
	))
	keyEnv, ok := a.until(cur.KeyEnv, func(v string) (string, error) { return checkVarName(a.s, v) })
	if !ok {
		return jarxdir.LLM{}, false
	}
	if _, set := llm.KeyFrom(a.lookup, keyEnv); set {
		a.p.AnswerOK(a.text(keyEnv+" is set in this terminal"), redact.Text{})
	} else {
		a.p.AnswerNote(a.text(keyEnv + " isn't set in this terminal. to set it without it landing in shell history:"))
		a.p.Commands(setKeyCommands(a, keyEnv))
	}
	a.p.Blank()
	return jarxdir.LLM{BaseURL: base, Model: model, KeyEnv: keyEnv}, true
}

// confirmSave shows the summary and saves on a yes. When saved is false,
// the caller returns code.
func (a *asker) confirmSave(env platform.Env, cfg jarxdir.Config) (bool, int) {
	a.p.LLMSummary(llmView(a.s, a.lookup, *cfg.LLM))
	a.p.Blank()
	a.p.YesNo(a.text("save to "+homeShort(env, configPath(env))+"?"), true, nil)
	yes, ok := a.yesNo(true)
	switch {
	case !ok:
		return false, a.quit()
	case !yes:
		a.p.Say(a.text("not saved"))
		return false, exitOK
	}
	if err := save(env, cfg); err != nil {
		a.p.Error(err)
		return false, exitError
	}
	a.saved = true
	a.p.Say(a.text("saved"))
	return true, exitOK
}

// setKeyCommands are the commands that set the key's var without echo and
// keep the key out of shell history.
func setKeyCommands(a *asker, name string) []report.Command {
	ps, sh := keyCommands(name)
	return []report.Command{
		{Label: a.text("powershell"), Text: a.text(ps)},
		{Label: a.text("bash, zsh"), Text: a.text(sh)},
	}
}

// keyCommands are the PowerShell and the bash and zsh commands that set
// the var name without echo.
func keyCommands(name string) (string, string) {
	return "$env:" + name + " = [Net.NetworkCredential]::new('', (Read-Host -AsSecureString 'key')).Password",
		"read -rs " + name + " && export " + name
}

// offerTest asks whether to test the connection (default no, since it's a
// network call) and runs it on a yes.
func (a *asker) offerTest(c jarxdir.LLM, key llm.Key) int {
	u, _ := url.Parse(c.BaseURL) // checked before it was saved
	host := u.Host
	a.p.Blank()
	a.p.YesNo(a.text("test the connection?"), false, a.texts("sends one short request with no scan content to "+host))
	yes, ok := a.yesNo(false)
	switch {
	case !ok && a.interrupted:
		return a.quit()
	case !ok || !yes:
		return exitOK
	}
	took, err := a.ping(c, key)
	if a.interrupted {
		return a.quit()
	}
	if err != nil {
		a.p.AnswerNote(a.text(err.Error()))
		a.p.Hint(a.text("the settings are saved. fix it and run jarx setup llm again"))
		return exitError
	}
	a.p.AnswerOK(a.text(host+" answered as "+c.Model), a.text(took.Round(time.Millisecond).String()))
	return exitOK
}

// ping runs the connection test, and stops it on ctrl+c.
func (a *asker) ping(c jarxdir.LLM, key llm.Key) (time.Duration, error) {
	var took time.Duration
	var err error
	a.whileCatching(pingWait, func(ctx context.Context) {
		took, err = llm.Ping(ctx, netguard.NewLLM(), c.BaseURL, c.Model, key)
	})
	return took, err //nolint:wrapcheck // llm errors already say what failed
}

// whileCatching runs f with a context that ctrl+c cancels, and a timeout
// when one is given. After ctrl+c, a.interrupted is set.
func (a *asker) whileCatching(timeout time.Duration, f func(context.Context)) {
	ctx, cancel := context.WithCancel(context.Background())
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
	}
	defer cancel()
	stopped := make(chan struct{})
	go func() {
		select {
		case <-a.sig:
			close(stopped)
			cancel()
		case <-ctx.Done():
		}
	}()
	f(ctx)
	cancel()
	select {
	case <-stopped:
		a.interrupted = true
	default:
	}
}
