package reach

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
)

// world is one Claude project with its settings, on a fake home, and the
// machine's credentials.
type world struct {
	t     *testing.T
	s     *redact.Scrubber
	env   platform.Env
	proj  model.Project
	perm  model.Permissions
	creds []model.Credential
}

func newWorld(t *testing.T, goos, jarxEnv string) *world {
	t.Helper()
	home := t.TempDir()
	if jarxEnv != "" {
		if err := writeFile(filepath.Join(home, platform.JarxEnvName), jarxEnv); err != nil {
			t.Fatal(err)
		}
	}
	env, err := platform.FromHome(home)
	if err != nil {
		t.Fatal(err)
	}
	env.GOOS = goos
	s, err := redact.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, s: s, env: env}
	dir := filepath.Join(home, "code", "app")
	w.proj = model.Project{
		Path: model.NewPath(s, dir), Status: model.ProjectOK,
		Origins: []model.Origin{{Agent: model.AgentClaude, InEffect: true}},
	}
	w.perm = model.Permissions{Agent: model.AgentClaude, StartMode: w.text("default"), StartWhy: w.text("defaultMode is default")}
	w.creds = []model.Credential{w.file("aws", ".aws/credentials")}
	return w
}

func (w *world) text(v string) redact.Text {
	t, _ := w.s.Scrub(v)
	return t
}

func (w *world) home(rel string) string { return filepath.Join(w.env.Home, filepath.FromSlash(rel)) }

func (w *world) file(kind, rel string) model.Credential {
	return model.Credential{Kind: model.CredentialKind(kind), Path: model.NewPath(w.s, w.home(rel)), Read: model.ReadOK}
}

func (w *world) user() model.Origin {
	return model.Origin{Agent: model.AgentClaude, Scope: model.ScopeUser, File: model.NewPath(w.s, w.home(".claude/settings.json")), InEffect: true}
}

// rule adds a user settings rule; target is what's inside the parens.
func (w *world) rule(action model.RuleAction, rule string) *world {
	target := ""
	if i := strings.IndexByte(rule, '('); i >= 0 && strings.HasSuffix(rule, ")") {
		target = rule[i+1 : len(rule)-1]
	}
	if strings.HasPrefix(rule, "sandbox.") {
		_, target, _ = strings.Cut(rule, " ")
	}
	w.perm.Rules = append(w.perm.Rules, model.PermissionRule{Action: action, Rule: w.text(rule), Target: w.text(target), Origin: w.user()})
	return w
}

func (w *world) option(key, value string) *world {
	w.perm.Options = append(w.perm.Options, model.Option{Key: w.text(key), Setting: model.Setting[redact.Text]{
		Layers: []model.Layer[redact.Text]{{Value: w.text(value), Origin: w.user()}},
	}})
	return w
}

func (w *world) start(mode string) {
	w.perm.StartMode, w.perm.StartWhy = w.text(mode), w.text("defaultMode is "+mode)
}

func (w *world) sandbox() *world { return w.option("sandbox.enabled", "true") }

// settle runs Settle and gives the verdict for a credential on a channel.
func (w *world) settle() []model.Project {
	w.t.Helper()
	w.proj.Permissions = []model.Permissions{w.perm}
	ps := []model.Project{w.proj}
	Settle(w.s, w.env, ps, w.creds)
	return ps
}

func (w *world) verdict(ch model.ReachChannel, what string) (model.ReachVerdict, string) {
	w.t.Helper()
	for _, r := range w.settle()[0].Reach {
		label := r.Name.String()
		if !r.Path.IsZero() {
			label = r.Path.Raw()
		}
		if r.Channel == ch && (label == what || label == w.home(what)) {
			why := make([]string, 0, len(r.Why))
			for _, y := range r.Why {
				why = append(why, y.String())
			}
			return r.Verdict, strings.Join(why, "; ")
		}
	}
	w.t.Fatalf("no %s verdict for %s", ch, what)
	return "", ""
}

const awsCreds = ".aws/credentials"

func TestFileTools(t *testing.T) {
	for name, tc := range map[string]struct {
		set  func(*world)
		want model.ReachVerdict
		why  string
	}{
		"outside the working dirs asks": {func(*world) {}, model.ReachApproval, "outside the working dirs"},
		"auto: a classifier approves":   {func(w *world) { w.start("auto") }, model.ReachSilent, "classifier"},
		"bypass skips the prompt":       {func(w *world) { w.start("bypassPermissions") }, model.ReachSilent, "bypassPermissions"},
		"dontAsk denies it":             {func(w *world) { w.start("dontAsk") }, model.ReachBlocked, "dontAsk"},
		"a deny blocks":                 {func(w *world) { w.rule(model.RuleDeny, "Read(~/.aws/**)") }, model.ReachBlocked, "Read(~/.aws/**)"},
		"an ask holds in bypass": {func(w *world) {
			w.rule(model.RuleAsk, "Read(~/.aws/**)").start("bypassPermissions")
		}, model.ReachApproval, "every mode"},
		"an allow reads it":               {func(w *world) { w.rule(model.RuleAllow, "Read(~/.aws/**)") }, model.ReachSilent, "Read(~/.aws/**)"},
		"an Edit allow reads it":          {func(w *world) { w.rule(model.RuleAllow, "Edit(~/.aws/**)") }, model.ReachSilent, "Edit(~/.aws/**)"},
		"blockReads refuses it":           {func(w *world) { w.option("permissions.blockReadsOutsideWorkingDirectories", "true") }, model.ReachBlocked, "blockReadsOutsideWorkingDirectories"},
		"an added dir is inside":          {func(w *world) { w.addDir("~/.aws") }, model.ReachSilent, "working dirs"},
		"an Edit deny doesn't stop reads": {func(w *world) { w.rule(model.RuleDeny, "Edit(~/.aws/**)") }, model.ReachApproval, "outside"},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, "linux", "")
			tc.set(w)
			if got, why := w.verdict(model.ChannelFileTools, awsCreds); got != tc.want || !strings.Contains(why, tc.why) {
				t.Errorf("file tools = %s (%q), want %s with a reason naming %q", got, why, tc.want, tc.why)
			}
		})
	}
}

func (w *world) addDir(p string) *world {
	w.perm.AdditionalDirectories = append(w.perm.AdditionalDirectories, model.Layer[redact.Text]{Value: w.text(p), Origin: w.user()})
	return w
}

func TestAFileInTheProjectIsInsideTheWorkingDirs(t *testing.T) {
	w := newWorld(t, "linux", "")
	env := filepath.Join(w.proj.Path.Raw(), ".env")
	w.proj.Credentials = []model.Credential{{Kind: "env_file", Path: model.NewPath(w.s, env), Read: model.ReadOK}}

	if got, _ := w.verdict(model.ChannelFileTools, env); got != model.ReachSilent {
		t.Errorf("file tools on the project's .env = %s, want readable silently", got)
	}
}

func TestAWholeDirCredentialIsCoveredByARuleOnItsFiles(t *testing.T) {
	w := newWorld(t, "linux", "")
	gcloud := w.file("gcloud", ".config/gcloud")
	gcloud.Dir = true
	w.creds = []model.Credential{gcloud}
	w.rule(model.RuleDeny, "Read(~/.config/gcloud/**)")

	if got, _ := w.verdict(model.ChannelFileTools, ".config/gcloud"); got != model.ReachBlocked {
		t.Errorf("file tools on the gcloud dir = %s, want blocked by the rule on its files", got)
	}
}

func TestShell(t *testing.T) {
	for name, tc := range map[string]struct {
		goos string
		set  func(*world)
		want model.ReachVerdict
		why  string
	}{
		"no sandbox: cat runs silently":    {"linux", func(*world) {}, model.ReachSilent, "read-only"},
		"no sandbox: a deny is bypassable": {"linux", func(w *world) { w.rule(model.RuleDeny, "Read(~/.aws/**)") }, model.ReachBypassable, "grep -r"},
		"no sandbox: blockReads asks in every mode": {"linux", func(w *world) {
			w.option("permissions.blockReadsOutsideWorkingDirectories", "true").start("bypassPermissions")
		}, model.ReachApproval, "every mode"},
		"windows has no sandbox": {"windows", func(w *world) { w.sandbox() }, model.ReachSilent, "Windows"},
		"sandbox: default reads": {"linux", func(w *world) { w.sandbox() }, model.ReachSilent, "sandbox"},
		"sandbox: filesystem off": {"linux", func(w *world) {
			w.sandbox().option("sandbox.filesystem.disabled", "true")
		}, model.ReachSilent, "filesystem.disabled"},
		"sandbox: denyRead, the retry asks": {"linux", func(w *world) {
			w.sandbox().rule(model.RuleDeny, "sandbox.filesystem.denyRead ~/.aws")
		}, model.ReachApproval, "retry"},
		"sandbox: no retry": {"linux", func(w *world) {
			w.sandbox().rule(model.RuleDeny, "sandbox.filesystem.denyRead ~/.aws").option("sandbox.allowUnsandboxedCommands", "false")
		}, model.ReachBlocked, "allowUnsandboxedCommands"},
		"sandbox: bypass retries silently": {"linux", func(w *world) {
			w.sandbox().rule(model.RuleDeny, "sandbox.filesystem.denyRead ~/.aws").start("bypassPermissions")
		}, model.ReachSilent, "bypassPermissions"},
		"sandbox: auto retries with the classifier": {"linux", func(w *world) {
			w.sandbox().rule(model.RuleDeny, "sandbox.filesystem.denyRead ~/.aws").start("auto")
		}, model.ReachSilent, "classifier"},
		"sandbox: dontAsk denies the retry": {"linux", func(w *world) {
			w.sandbox().rule(model.RuleDeny, "sandbox.filesystem.denyRead ~/.aws").start("dontAsk")
		}, model.ReachBlocked, "dontAsk"},
		"sandbox: an allow approves the retry": {"linux", func(w *world) {
			w.sandbox().rule(model.RuleDeny, "sandbox.filesystem.denyRead ~/.aws").rule(model.RuleAllow, "Bash(cat *)")
		}, model.ReachSilent, "Bash(cat *)"},
		"sandbox: an ask on the retry holds in bypass": {"linux", func(w *world) {
			w.sandbox().rule(model.RuleDeny, "sandbox.filesystem.denyRead ~/.aws").
				rule(model.RuleAsk, "Bash(dangerouslyDisableSandbox:true)").start("bypassPermissions")
		}, model.ReachApproval, "dangerouslyDisableSandbox"},
		"sandbox: a credentials.files deny": {"linux", func(w *world) {
			w.sandbox().rule(model.RuleDeny, "sandbox.credentials.files ~/.aws/credentials")
		}, model.ReachApproval, "credentials.files"},
		"sandbox: a narrower allowRead reopens": {"linux", func(w *world) {
			w.sandbox().rule(model.RuleDeny, "sandbox.filesystem.denyRead ~/").rule(model.RuleRead, "sandbox.filesystem.allowRead ~/.aws")
		}, model.ReachSilent, "allowRead"},
		"sandbox: a deny inside a wider allow holds": {"linux", func(w *world) {
			w.sandbox().rule(model.RuleRead, "sandbox.filesystem.allowRead ~/").rule(model.RuleDeny, "sandbox.filesystem.denyRead ~/.aws").
				option("sandbox.allowUnsandboxedCommands", "false")
		}, model.ReachBlocked, "denyRead"},
		"sandbox: masked": {"linux", func(w *world) {
			w.sandbox().rule(model.RuleMask, "sandbox.credentials.files ~/.aws/credentials")
		}, model.ReachBlocked, "stand-in"},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, tc.goos, "")
			tc.set(w)
			if got, why := w.verdict(model.ChannelShell, awsCreds); got != tc.want || !strings.Contains(why, tc.why) {
				t.Errorf("shell = %s (%q), want %s with a reason naming %q", got, why, tc.want, tc.why)
			}
		})
	}
}

func TestEnvVars(t *testing.T) {
	for name, tc := range map[string]struct {
		jarxEnv string
		set     func(*world)
		varName string
		want    model.ReachVerdict
		why     string
	}{
		"bash inherits it":              {"NPM_TOKEN=x\n", func(*world) {}, "NPM_TOKEN", model.ReachSilent, "inherits"},
		"the scrub strips it":           {"NPM_TOKEN=x\nCLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1\n", func(*world) {}, "NPM_TOKEN", model.ReachBlocked, "SUBPROCESS_ENV_SCRUB"},
		"the scrub keeps GitHub tokens": {"GITHUB_TOKEN=x\nCLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1\n", func(*world) {}, "GITHUB_TOKEN", model.ReachSilent, "GitHub"},
		"a sandbox envVars deny": {"NPM_TOKEN=x\n", func(w *world) {
			w.sandbox().rule(model.RuleDeny, "sandbox.credentials.envVars NPM_TOKEN")
		}, "NPM_TOKEN", model.ReachApproval, "envVars"},
		"a settings env name": {"", func(w *world) {
			w.perm.Env = []model.Layer[redact.Text]{{Value: w.text("DEPLOY_TOKEN"), Origin: w.user()}, {Value: w.text("EDITOR"), Origin: w.user()}}
		}, "DEPLOY_TOKEN", model.ReachSilent, "settings"},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, "linux", tc.jarxEnv)
			for _, n := range w.env.Names() {
				if n == "NPM_TOKEN" || n == "GITHUB_TOKEN" {
					w.creds = append(w.creds, model.Credential{Kind: "env_var", Name: w.text(n), Via: w.text("environment"), Read: model.ReadExistsOnly})
				}
			}
			tc.set(w)
			if got, why := w.verdict(model.ChannelShell, tc.varName); got != tc.want || !strings.Contains(why, tc.why) {
				t.Errorf("shell on %s = %s (%q), want %s with a reason naming %q", tc.varName, got, why, tc.want, tc.why)
			}
		})
	}
}

func TestASettingsEnvNameThatIsntASecretIsLeftOut(t *testing.T) {
	w := newWorld(t, "linux", "")
	w.perm.Env = []model.Layer[redact.Text]{{Value: w.text("EDITOR"), Origin: w.user()}}

	for _, r := range w.settle()[0].Reach {
		if r.Name.String() == "EDITOR" {
			t.Errorf("EDITOR got a verdict: %+v", r)
		}
	}
}

func TestLocalMCPServersAndHooksReadAsTheProcess(t *testing.T) {
	w := newWorld(t, "linux", "")
	o := model.Origin{Agent: model.AgentClaude, Scope: model.ScopeProject, InEffect: true}
	w.proj.Servers = []model.Server{
		{Name: w.text("notes"), Transport: model.TransportStdio, Start: model.StartYes, Origin: o},
		{Name: w.text("remote"), Transport: model.TransportHTTP, Start: model.StartYes, Origin: o},
		{Name: w.text("off"), Transport: model.TransportStdio, Start: model.StartNo, Origin: o},
	}
	w.proj.Hooks = []model.Hook{{Type: w.text("command"), Run: w.text("./fmt.sh"), Origin: o}}

	got, why := w.verdict(model.ChannelMCP, awsCreds)
	if got != model.ReachByTheProcess || !strings.Contains(why, "notes") || strings.Contains(why, "remote") || strings.Contains(why, "off") {
		t.Errorf("mcp = %s (%q), want the local server that starts, by the process", got, why)
	}
	if got, _ := w.verdict(model.ChannelHooks, awsCreds); got != model.ReachByTheProcess {
		t.Errorf("hooks = %s, want by the process", got)
	}
}

func TestOnlyProjectsClaudeKnowsGetClaudeVerdicts(t *testing.T) {
	w := newWorld(t, "linux", "")
	w.proj.Origins = []model.Origin{{Agent: model.AgentCodex, InEffect: true}}

	if ps := w.settle(); len(ps[0].Reach) != 0 {
		t.Errorf("reach = %+v, want none for a project only Codex knows", ps[0].Reach)
	}
}
