package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fake key the tests put in .jarx-env. It must never show up in output
// or in jarx's config.
const canaryLLMKey = "CANARYllmkey-0000-not-a-real-key"

// opts is how a test runs jarx: what's on stdin, whether it's a terminal,
// how ctrl+c arrives, and the env vars set in the terminal, where jarx
// reads the LLM key from. Nothing comes from the real env.
type opts struct {
	in          io.Reader
	interactive bool
	interrupt   func() (<-chan os.Signal, func())
	keys        map[string]string
}

// terminal is a terminal with these env vars set.
func terminal(keys map[string]string) opts { return opts{interactive: true, keys: keys} }

// ask runs jarx as if a person typed input into a terminal.
func ask(input string, args ...string) result { return opts{interactive: true}.ask(input, args...) }

// ask runs jarx with input typed into o's terminal.
func (o opts) ask(input string, args ...string) result {
	o.in = strings.NewReader(input)
	return o.run(args...)
}

// answers is what a person types: one answer per line, "" for Enter.
func answers(lines ...string) string { return strings.Join(lines, "\n") + "\n" }

// runIn runs jarx with input on stdin that isn't a terminal, like a pipe.
func runIn(input string, args ...string) result { return opts{}.ask(input, args...) }

func (o opts) run(args ...string) result {
	if !strings.Contains(strings.Join(args, " "), "--home") {
		return result{code: -1, stderr: "test helper: refusing a real-machine run, pass --home"}
	}
	if o.in == nil {
		o.in = strings.NewReader("")
	}
	keys := o.keys
	lookup := func(name string) (string, bool) { v, ok := keys[name]; return v, ok }
	var stdout, stderr bytes.Buffer
	code := runWith(args, streams{in: o.in, out: &stdout, err: &stderr, interactive: o.interactive, interrupt: o.interrupt, lookupKey: lookup}, "v1.2.3-test")
	out, banner := strings.CutPrefix(stdout.String(), bannerText)
	return result{code: code, stdout: out, stderr: stderr.String(), banner: banner}
}

// askThenCtrlC types input into o's terminal, then presses ctrl+c once
// jarx has read all of it and waits for more.
func (o opts) askThenCtrlC(t *testing.T, input string, args ...string) result {
	t.Helper()
	sig := make(chan os.Signal, 1)
	in := &ctrlCReader{data: []byte(input), press: func() { sig <- os.Interrupt }, done: make(chan struct{})}
	t.Cleanup(func() { close(in.done) })
	o.in, o.interactive = in, true
	o.interrupt = func() (<-chan os.Signal, func()) { return sig, func() {} }
	return o.run(args...)
}

// ctrlCReader gives its data, then presses ctrl+c and blocks like a
// terminal nobody types into.
type ctrlCReader struct {
	data    []byte
	press   func()
	pressed bool
	done    chan struct{}
}

func (r *ctrlCReader) Read(b []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(b, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	if !r.pressed {
		r.pressed = true
		r.press()
	}
	<-r.done
	return 0, io.EOF
}

type savedLLM struct {
	BaseURL string `json:"baseUrl"`
	Model   string `json:"model"`
	KeyEnv  string `json:"keyEnv"`
}

// savedConfig reads the fake home's config file as it is on disk.
func savedConfig(t *testing.T, home string) (string, *savedLLM) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, ".jarx-state", "config.json")) //nolint:gosec // G304: test temp path
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		LLM *savedLLM `json:"llm"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	return string(data), cfg.LLM
}

func tilde(rest ...string) string {
	return "~" + string(filepath.Separator) + filepath.Join(rest...)
}

func TestSetupShowsSettingsAsATree(t *testing.T) {
	home := fakeHome(t, "")

	got := run("setup", "--home", home)

	want := "jarx settings\n" +
		"+- state dir  " + tilde(".jarx-state") + "  not created yet\n" +
		"+- repos      none\n" +
		`\- llm        off  (jarx setup llm)` + "\n"
	if got.code != 0 || got.stdout != want {
		t.Errorf("setup = %d, stdout\n%s\nwant\n%s(stderr %q)", got.code, got.stdout, want, got.stderr)
	}
}

func TestSetupListsReposUnderTheirRow(t *testing.T) {
	home := fakeHome(t, "")
	workDir(t, home)
	run("setup", "--home", home, "repo", "add", filepath.Join(home, "work"))
	if err := os.RemoveAll(filepath.Join(home, "work")); err != nil {
		t.Fatal(err)
	}

	got := run("setup", "--home", home)

	if want := "+- repos      1\n|  \\- " + tilde("work") + "  missing\n"; !strings.Contains(got.stdout, want) {
		t.Errorf("setup stdout\n%s\nwant it to contain\n%s", got.stdout, want)
	}
}

func TestSetupLLMWithoutATerminalSaysHowToScriptIt(t *testing.T) {
	home := fakeHome(t, "")

	got := runIn("https://llm.example.com/v1\nm-1\n\ny\n", "setup", "--home", home, "llm")

	if got.code != 2 {
		t.Errorf("exit = %d, want 2", got.code)
	}
	for _, want := range []string{"needs a terminal", "jarx setup llm --url https://llm.example.com/v1 --model <model> --key-env JARX_LLM_KEY"} {
		if !strings.Contains(got.stderr, want) {
			t.Errorf("stderr = %q, want it to contain %q", got.stderr, want)
		}
	}
	if strings.Contains(got.stdout, "1/3") {
		t.Errorf("stdout = %q, want no questions without a terminal", got.stdout)
	}
	if _, err := os.Stat(filepath.Join(home, ".jarx-state")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("created the state dir (err %v), want nothing saved", err)
	}
}

func TestSetupLLMFlagsSaveWithoutATerminal(t *testing.T) {
	home := fakeHome(t, "")

	got := runIn("", "setup", "llm", "--home", home, "--url", "https://llm.example.com/v1", "--model", "m-1", "--key-env", "MY_KEY")

	if got.code != 0 {
		t.Fatalf("exit = %d, stderr %q", got.code, got.stderr)
	}
	want := "llm review\n" +
		"+- endpoint  https://llm.example.com/v1\n" +
		"+- model     m-1\n" +
		`\- key       from MY_KEY  not set in this terminal` + "\n" +
		"\nsaved to " + tilde(".jarx-state", "config.json") + "\n"
	if got.stdout != want {
		t.Errorf("stdout\n%s\nwant\n%s", got.stdout, want)
	}
	if _, llm := savedConfig(t, home); llm == nil || *llm != (savedLLM{"https://llm.example.com/v1", "m-1", "MY_KEY"}) {
		t.Errorf("saved llm = %+v", llm)
	}
}

func TestSetupLLMFlagsNeedAllThree(t *testing.T) {
	home := fakeHome(t, "")
	for name, args := range map[string][]string{
		"no model": {"--url", "https://llm.example.com/v1", "--key-env", "K"},
		"no url":   {"--model", "m", "--key-env", "K"},
		"no var":   {"--url", "https://llm.example.com/v1", "--model", "m"},
		"extra":    {"--url", "https://llm.example.com/v1", "--model", "m", "--key-env", "K", "more"},
	} {
		got := runIn("", append([]string{"setup", "llm", "--home", home}, args...)...)

		if got.code != 2 || !strings.Contains(got.stderr, "usage: jarx setup") {
			t.Errorf("%s: exit %d, stderr %q; want 2 with usage", name, got.code, got.stderr)
		}
	}
	if _, llm := savedConfig(t, home); llm != nil {
		t.Errorf("saved %+v, want nothing", llm)
	}
}

// A GitHub token shape the secret patterns know.
const tokenShaped = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" //nolint:gosec // G101: a made-up token shape for tests

func TestSetupLLMFlagsRefuseBadAnswers(t *testing.T) {
	home := fakeHome(t, "")
	ok := map[string]string{"--url": "https://llm.example.com/v1", "--model": "m-1", "--key-env": "JARX_LLM_KEY"}
	for _, tc := range []struct {
		flag, value, want string
	}{
		{"--url", "http://llm.example.com/v1", "plain http only goes to loopback"},
		{"--url", "https://u:p@llm.example.com/v1", "a user, password, query or fragment"},
		{"--url", "https://llm.example.com/v1?key=abc", "a user, password, query or fragment"},
		{"--url", "llm.example.com", "not a full URL"},
		{"--url", "https://llm.example.com/" + tokenShaped, "looks like a key"},
		{"--model", tokenShaped, "looks like a key"},
		{"--model", "sk-proj-abcdefghijklmnop", "looks like a key"},
		{"--model", "two words", "no spaces"},
		{"--key-env", "MY-KEY", "letters, digits and _"},
		{"--key-env", "1KEY", "letters, digits and _"},
		{"--key-env", tokenShaped, "looks like a key"},
	} {
		args := make([]string, 0, 4+2*len(ok))
		args = append(args, "setup", "llm", "--home", home)
		for f, v := range ok {
			if f == tc.flag {
				v = tc.value
			}
			args = append(args, f, v)
		}

		got := runIn("", args...)

		if got.code != 1 || !strings.Contains(got.stderr, tc.want) {
			t.Errorf("%s %q: exit %d, stderr %q; want 1 with %q", tc.flag, tc.value, got.code, got.stderr, tc.want)
		}
		if strings.Contains(got.stdout+got.stderr, tokenShaped) {
			t.Errorf("%s %q: the key-shaped value shows in the output", tc.flag, tc.value)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".jarx-state")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a refused setup created the state dir (err %v)", err)
	}
}

func TestSetupShowsTheLLMRowOnceSaved(t *testing.T) {
	home := fakeHome(t, "")
	runIn("", "setup", "llm", "--home", home, "--url", "https://llm.example.com/v1", "--model", "m-1", "--key-env", "JARX_LLM_KEY")

	got := opts{keys: map[string]string{"JARX_LLM_KEY": canaryLLMKey}}.run("setup", "--home", home)

	if want := `\- llm        https://llm.example.com/v1 - m-1 - key from JARX_LLM_KEY  set` + "\n"; !strings.HasSuffix(got.stdout, want) {
		t.Errorf("setup stdout\n%s\nwant it to end with\n%s", got.stdout, want)
	}
	if strings.Contains(got.stdout+got.stderr, canaryLLMKey) {
		t.Error("setup shows the key")
	}
}

func TestSetupLLMOffClearsTheSettings(t *testing.T) {
	home := fakeHome(t, "")
	runIn("", "setup", "llm", "--home", home, "--url", "https://llm.example.com/v1", "--model", "m-1", "--key-env", "MY_KEY")

	got := run("setup", "--home", home, "llm", "off")

	want := "llm review is off. removed the endpoint, model and key var name\n" +
		"your MY_KEY env var is untouched\n"
	if got.code != 0 || got.stdout != want {
		t.Errorf("off = %d, %q; want %q (stderr %q)", got.code, got.stdout, want, got.stderr)
	}
	if data, llm := savedConfig(t, home); llm != nil || strings.Contains(data, "llm") {
		t.Errorf("config after off = %s, want no llm settings", data)
	}
}

func TestSetupLLMOffWhenAlreadyOffWritesNothing(t *testing.T) {
	home := fakeHome(t, "")

	got := run("setup", "llm", "off", "--home", home)

	if got.code != 0 || got.stdout != "llm review is already off\n" {
		t.Errorf("off = %d, %q (stderr %q)", got.code, got.stdout, got.stderr)
	}
	if _, err := os.Stat(filepath.Join(home, ".jarx-state")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("created the state dir (err %v), want nothing written", err)
	}
}

func TestSetupLLMAsksOneQuestionAtATime(t *testing.T) {
	home := fakeHome(t, "")
	input := "http://llm.example.com/v1\n" + // refused: plain http, not loopback
		"https://llm.example.com/v1\n" +
		"\n" + // refused: no model yet
		"m-1\n" +
		"\n" + // the default var name
		"\n" // save, the default

	got := ask(input, "setup", "--home", home, "llm")

	if got.code != 0 {
		t.Fatalf("exit = %d, stderr %q\n%s", got.code, got.stderr, got.stdout)
	}
	want := "llm review setup\n" +
		"+- jarx sends one masked artifact at a time to an OpenAI-compatible endpoint\n" +
		"+- the key stays in an env var you set. jarx never stores it\n" +
		`\- enter keeps the default - ctrl+c quits without saving` + "\n" +
		"\n" +
		"1/3  base url\n" +
		"     an OpenAI-compatible endpoint: https, or http on loopback only\n" +
		"     like https://api.openai.com/v1 or http://127.0.0.1:11434/v1\n" +
		"  >  " +
		`     \- plain http only goes to loopback (127.0.0.1, ::1, localhost)` + "\n" +
		"  >  " +
		`     \- ok  https - llm.example.com` + "\n" +
		"\n" +
		"2/3  model\n" +
		"     the model name your endpoint expects\n" +
		"  >  " +
		`     \- a model is needed` + "\n" +
		"  >  " +
		"\n" +
		"3/3  key env var  [JARX_LLM_KEY]\n" +
		"     the name of the env var that holds the key, read only when jarx sends\n" +
		"     set it only in the terminal you run jarx from. a key in your shell profile\n" +
		"     is in every agent's env too, so the agents can read it\n" +
		"  >  " +
		`     \- JARX_LLM_KEY isn't set in this terminal. to set it without it landing in` + "\n" +
		"        shell history:\n" +
		"        powershell  $env:JARX_LLM_KEY = [Net.NetworkCredential]::new('', (Read-Host -AsSecureString 'key')).Password\n" +
		"        bash, zsh   read -rs JARX_LLM_KEY && export JARX_LLM_KEY\n" +
		"\n" +
		"llm review\n" +
		"+- endpoint  https://llm.example.com/v1\n" +
		"+- model     m-1\n" +
		`\- key       from JARX_LLM_KEY  not set in this terminal` + "\n" +
		"\n" +
		"save to " + tilde(".jarx-state", "config.json") + "?  [Y/n]\n" +
		"  >  " +
		"saved\n" +
		"set JARX_LLM_KEY, then run jarx setup llm again to test the connection\n"
	if got.stdout != want {
		t.Errorf("stdout\n%s\nwant\n%s", got.stdout, want)
	}
	if _, llm := savedConfig(t, home); llm == nil || *llm != (savedLLM{"https://llm.example.com/v1", "m-1", "JARX_LLM_KEY"}) {
		t.Errorf("saved llm = %+v", llm)
	}
}

func TestSetupLLMDefaultsAreTheSavedValues(t *testing.T) {
	home := fakeHome(t, "")
	runIn("", "setup", "llm", "--home", home, "--url", "https://llm.example.com/v1", "--model", "m-1", "--key-env", "MY_KEY")

	got := ask("\n\n\n\n", "setup", "--home", home, "llm")

	for _, want := range []string{
		"1/3  base url  [https://llm.example.com/v1]\n",
		"2/3  model  [m-1]\n",
		"3/3  key env var  [MY_KEY]\n",
	} {
		if !strings.Contains(got.stdout, want) {
			t.Errorf("stdout = %q, want it to contain %q", got.stdout, want)
		}
	}
	if _, llm := savedConfig(t, home); llm == nil || *llm != (savedLLM{"https://llm.example.com/v1", "m-1", "MY_KEY"}) {
		t.Errorf("saved llm = %+v, want the old values kept", llm)
	}
}

func TestSetupLLMEndOfInputSavesNothing(t *testing.T) {
	home := fakeHome(t, "")

	got := ask("https://llm.example.com/v1\nm-1\n", "setup", "--home", home, "llm")

	if got.code != 1 || !strings.HasSuffix(got.stdout, "\ncancelled, nothing saved\n") {
		t.Errorf("exit %d, stdout %q; want 1 and cancelled, nothing saved", got.code, got.stdout)
	}
	if _, err := os.Stat(filepath.Join(home, ".jarx-state")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("created the state dir (err %v)", err)
	}
}

func TestSetupLLMAnsweringNoSavesNothing(t *testing.T) {
	home := fakeHome(t, "")

	got := ask("https://llm.example.com/v1\nm-1\n\nmaybe\nn\n", "setup", "--home", home, "llm")

	if got.code != 0 || !strings.Contains(got.stdout, "answer y or n") || !strings.HasSuffix(got.stdout, "not saved\n") {
		t.Errorf("exit %d, stdout %q; want a re-ask, then not saved", got.code, got.stdout)
	}
	if _, llm := savedConfig(t, home); llm != nil {
		t.Errorf("saved %+v, want nothing", llm)
	}
}

func TestSetupLLMSaysWhenTheVarIsSet(t *testing.T) {
	home := fakeHome(t, "")

	got := terminal(map[string]string{"MY_KEY": canaryLLMKey}).ask("https://llm.example.com/v1\nm-1\nMY_KEY\ny\nn\n", "setup", "--home", home, "llm")

	for _, want := range []string{`\- ok  MY_KEY is set in this terminal`, "key       from MY_KEY  set in this terminal", "test the connection?  [y/N]\n"} {
		if !strings.Contains(got.stdout, want) {
			t.Errorf("stdout = %q, want it to contain %q", got.stdout, want)
		}
	}
	if strings.Contains(got.stdout+got.stderr, canaryLLMKey) {
		t.Error("the output shows the key")
	}
}

// fakeLLM is an OpenAI-compatible endpoint on loopback that counts requests
// and keeps the last Authorization header.
type fakeLLM struct {
	requests int
	auth     string
	body     string
}

func (f *fakeLLM) serve(t *testing.T, status int) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests++
		f.auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		f.body = string(b)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"ok"}}]}`)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/v1"
}

func TestSetupLLMTestsTheConnectionOnlyWhenAsked(t *testing.T) {
	home := fakeHome(t, "")
	term := terminal(map[string]string{"JARX_LLM_KEY": canaryLLMKey})
	f := &fakeLLM{}
	base := f.serve(t, http.StatusOK)

	got := term.ask(base+"\nm-1\n\ny\n\n", "setup", "--home", home, "llm")

	if got.code != 0 || f.requests != 0 {
		t.Errorf("exit %d with %d requests, want 0 and none: the test defaults to no", got.code, f.requests)
	}
	if !strings.Contains(got.stdout, "sends one short request with no scan content to 127.0.0.1:") {
		t.Errorf("stdout = %q, want the test question to say what it sends and where", got.stdout)
	}

	got = term.ask(answers(base, "m-1", "", "y", "y"), "setup", "--home", home, "llm")

	if got.code != 0 || f.requests != 1 {
		t.Fatalf("exit %d with %d requests, want 0 and one (stderr %q)", got.code, f.requests, got.stderr)
	}
	if !strings.Contains(got.stdout, `\- ok  127.0.0.1:`) || !strings.Contains(got.stdout, " answered as m-1  ") {
		t.Errorf("stdout = %q, want the ok line", got.stdout)
	}
	if f.auth != "Bearer "+canaryLLMKey {
		t.Errorf("Authorization = %q, want the key from the named var", f.auth)
	}
	data, _ := savedConfig(t, home)
	if strings.Contains(got.stdout+got.stderr+data+f.body, canaryLLMKey) {
		t.Error("the key shows up in the output, the config or the request body")
	}
}

func TestSetupLLMConnectionTestFailureSaysWhy(t *testing.T) {
	home := fakeHome(t, "")
	f := &fakeLLM{}
	base := f.serve(t, http.StatusUnauthorized)

	got := terminal(map[string]string{"JARX_LLM_KEY": canaryLLMKey}).ask(answers(base, "m-1", "", "y", "y"), "setup", "--home", home, "llm")

	if got.code != 1 || !strings.Contains(got.stdout, "the endpoint rejected the key (HTTP 401)") {
		t.Errorf("exit %d, stdout %q; want 1 with the reason", got.code, got.stdout)
	}
	if !strings.Contains(got.stdout, "saved\n") {
		t.Errorf("stdout = %q, want the settings saved before the test", got.stdout)
	}
	if strings.Contains(got.stdout+got.stderr, canaryLLMKey) {
		t.Error("the output shows the key")
	}
}

func TestSetupLLMCtrlCSavesNothingAndSaysSo(t *testing.T) {
	home := fakeHome(t, "")

	got := opts{}.askThenCtrlC(t, answers("https://llm.example.com/v1"), "setup", "--home", home, "llm")

	if got.code != 130 || !strings.HasSuffix(got.stdout, "  >  \ncancelled, nothing saved\n") {
		t.Errorf("exit %d, stdout %q; want 130 ending in cancelled, nothing saved", got.code, got.stdout)
	}
	if _, err := os.Stat(filepath.Join(home, ".jarx-state")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("created the state dir (err %v)", err)
	}
}

func TestSetupLLMCtrlCAfterSavingSaysTheSettingsAreSaved(t *testing.T) {
	home := fakeHome(t, "")
	f := &fakeLLM{}
	base := f.serve(t, http.StatusOK)

	got := terminal(map[string]string{"JARX_LLM_KEY": canaryLLMKey}).askThenCtrlC(t, answers(base, "m-1", "", "y"), "setup", "--home", home, "llm")

	if got.code != 130 || !strings.HasSuffix(got.stdout, "\ncancelled. the settings are saved\n") {
		t.Errorf("exit %d, stdout %q; want 130 ending in cancelled, settings saved", got.code, got.stdout)
	}
	if _, llm := savedConfig(t, home); llm == nil || f.requests != 0 {
		t.Errorf("saved %+v with %d requests, want saved and no test sent", llm, f.requests)
	}
}

func TestTheKeyComesFromTheTerminalNotTheFakeHome(t *testing.T) {
	// Under --home every other var comes from .jarx-env, but the key is set
	// in the terminal jarx runs in, so a key in a file never counts.
	home := fakeHome(t, "JARX_LLM_KEY="+canaryLLMKey+"\n")
	runIn("", "setup", "llm", "--home", home, "--url", "https://llm.example.com/v1", "--model", "m-1", "--key-env", "JARX_LLM_KEY")

	got := run("setup", "--home", home)

	if !strings.HasSuffix(got.stdout, "key from JARX_LLM_KEY  not set\n") {
		t.Errorf("setup stdout = %q, want the key not set: .jarx-env doesn't count", got.stdout)
	}
}
