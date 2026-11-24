package reach

import (
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// exposure is the states and via for a credential, by its path or name.
func (w *world) exposure(a model.Agent, what string) ([]model.CredentialState, string, bool) {
	w.t.Helper()
	for _, e := range w.settle()[0].Exposure {
		label := e.Name.String() + " " + e.Path.Raw()
		if e.Agent == a && (strings.TrimSpace(label) == w.home(what) || strings.Contains(label, what)) {
			via := make([]string, 0, len(e.Via))
			for _, v := range e.Via {
				via = append(via, v.String())
			}
			return e.States, strings.Join(via, "; "), true
		}
	}
	return nil, "", false
}

func states(ss ...model.CredentialState) []model.CredentialState { return ss }

func TestACredentialAChannelReadsCanBeRead(t *testing.T) {
	w := newWorld(t, "linux", "")

	if got, _, _ := w.exposure(model.AgentClaude, awsCreds); !slices.Equal(got, states(model.StateCanRead)) {
		t.Errorf("states = %q, want can read", got)
	}
}

func TestACredentialEveryChannelBlocksIsNotReachable(t *testing.T) {
	w := newWorld(t, "linux", "")
	w.rule(model.RuleDeny, "Read(~/.aws/**)")
	w.sandbox()
	w.rule(model.RuleDeny, "sandbox.filesystem.denyRead ~/.aws")
	w.option("sandbox.allowUnsandboxedCommands", "false")

	if got, _, _ := w.exposure(model.AgentClaude, awsCreds); !slices.Equal(got, states(model.StateUnreachable)) {
		t.Errorf("states = %q, want not reachable", got)
	}
}

func (w *world) server(name string, a model.Agent, start model.StartState) model.Server {
	return model.Server{Name: w.text(name), Transport: model.TransportStdio, Start: start,
		Origin: model.Origin{Agent: a, Scope: model.ScopeProject, File: model.NewPath(w.s, w.proj.Path.Raw()+"/.mcp.json"), InEffect: true}}
}

func TestAnEnvVarAServerReferencesCanBeUsed(t *testing.T) {
	for name, tc := range map[string]struct {
		agent model.Agent
		srv   func(*world) model.Server
	}{
		"claude ${VAR} in env": {model.AgentClaude, func(w *world) model.Server {
			s := w.server("notes", model.AgentClaude, model.StartYes)
			s.Env = []model.Pair{{Key: w.text("TOKEN"), Value: w.text("${NPM_TOKEN}")}}
			return s
		}},
		"claude ${VAR:-default} in a header": {model.AgentClaude, func(w *world) model.Server {
			s := w.server("notes", model.AgentClaude, model.StartMaybe)
			s.Headers = []model.Pair{{Key: w.text("Authorization"), Value: w.text("Bearer ${NPM_TOKEN:-none}")}}
			return s
		}},
		"codex bearer_token_env_var": {model.AgentCodex, func(w *world) model.Server {
			s := w.server("notes", model.AgentCodex, model.StartYes)
			s.BearerVar = w.text("NPM_TOKEN")
			return s
		}},
		"codex env_vars": {model.AgentCodex, func(w *world) model.Server {
			s := w.server("notes", model.AgentCodex, model.StartYes)
			s.ForwardEnv = []redact.Text{w.text("NPM_TOKEN")}
			return s
		}},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, "linux", "NPM_TOKEN=x\n")
			w.proj.Origins = append(w.proj.Origins, model.Origin{Agent: model.AgentCodex, InEffect: true})
			w.creds = append(w.creds, model.Credential{Kind: "env_var", Name: w.text("NPM_TOKEN"), Via: w.text("environment"), Read: model.ReadExistsOnly})
			w.proj.Servers = []model.Server{tc.srv(w)}

			got, via, _ := w.exposure(tc.agent, "NPM_TOKEN")
			if !slices.Contains(got, model.StateCanUse) || !strings.Contains(via, "notes") {
				t.Errorf("states = %q via %q, want can use through notes", got, via)
			}
		})
	}
}

func TestAServerThatDoesntStartHoldsNothing(t *testing.T) {
	w := newWorld(t, "linux", "NPM_TOKEN=x\n")
	w.creds = append(w.creds, model.Credential{Kind: "env_var", Name: w.text("NPM_TOKEN"), Read: model.ReadExistsOnly})
	s := w.server("off", model.AgentClaude, model.StartNo)
	s.Env = []model.Pair{{Key: w.text("TOKEN"), Value: w.text("${NPM_TOKEN}")}}
	w.proj.Servers = []model.Server{s}

	if got, _, _ := w.exposure(model.AgentClaude, "NPM_TOKEN"); slices.Contains(got, model.StateCanUse) {
		t.Errorf("states = %q, want no can use from a server that doesn't start", got)
	}
}

func TestAnInlineSecretInAServerCanBeUsed(t *testing.T) {
	w := newWorld(t, "linux", "")
	secret, _ := w.s.Secret("github_pat", "made-up-token-value")
	s := w.server("deploy", model.AgentClaude, model.StartYes)
	s.Env = []model.Pair{{Key: w.text("GITHUB_TOKEN"), Value: secret}}
	w.proj.Servers = []model.Server{s}

	got, via, ok := w.exposure(model.AgentClaude, "deploy")
	if !ok || !slices.Equal(got, states(model.StateCanUse)) || !strings.Contains(via, "github_pat") {
		t.Errorf("states = %q via %q (found %v), want can use with the secret's kind", got, via, ok)
	}
}

func TestASecretInTextTheAgentLoadsIsSeen(t *testing.T) {
	w := newWorld(t, "linux", "")
	secret, _ := w.s.Secret("github_pat", "made-up-token-value")
	md := model.Instruction{Kind: model.InstructionFile, Path: model.NewPath(w.s, w.proj.Path.Raw()+"/CLAUDE.md"), Read: model.ReadOK,
		Text: secret, Origin: model.Origin{Agent: model.AgentClaude, Scope: model.ScopeProject, InEffect: true}}
	off := md
	off.Path = model.NewPath(w.s, w.proj.Path.Raw()+"/OLD.md")
	off.Origin.InEffect = false
	w.proj.Instructions = []model.Instruction{md, off}
	w.proj.Origins = append(w.proj.Origins, model.Origin{Agent: model.AgentCodex, InEffect: true}) // so Codex could see it too

	got, via, ok := w.exposure(model.AgentClaude, "CLAUDE.md")
	if !ok || !slices.Equal(got, states(model.StateSees)) || !strings.Contains(via, "github_pat") {
		t.Errorf("states = %q via %q (found %v), want sees with the secret's kind", got, via, ok)
	}
	if _, _, ok := w.exposure(model.AgentClaude, "OLD.md"); ok {
		t.Error("a secret in text the agent doesn't load counts as seen")
	}
	if _, _, ok := w.exposure(model.AgentCodex, "CLAUDE.md"); ok {
		t.Error("Codex sees a secret in Claude's CLAUDE.md")
	}
}

func TestTheWorstStateComesFirst(t *testing.T) {
	w := newWorld(t, "linux", "NPM_TOKEN=x\n")
	w.creds = append(w.creds, model.Credential{Kind: "env_var", Name: w.text("NPM_TOKEN"), Via: w.text("environment"), Read: model.ReadExistsOnly})
	s := w.server("notes", model.AgentClaude, model.StartYes)
	s.Env = []model.Pair{{Key: w.text("TOKEN"), Value: w.text("${NPM_TOKEN}")}}
	w.proj.Servers = []model.Server{s}

	if got, _, _ := w.exposure(model.AgentClaude, "NPM_TOKEN"); !slices.Equal(got, states(model.StateCanRead, model.StateCanUse)) {
		t.Errorf("states = %q, want can read, then can use", got)
	}
}
