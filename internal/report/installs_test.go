package report

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/model"
)

func (f scanFixture) install(a model.Agent, m model.InstallMethod, rel, version, from string, onPath bool) model.Install {
	return model.Install{Agent: a, Method: m, Path: f.path(rel), BinDir: f.path(filepath.Dir(rel)), Version: f.text(version), VersionFrom: f.text(from), OnPath: onPath}
}

func TestTheAgentRowSaysWhichInstallRuns(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.Agents[0].Installs = []model.Install{
		f.install(model.AgentClaude, model.InstallNPM, "npm/claude", "2.1.250", "package.json", false),
		f.install(model.AgentClaude, model.InstallNative, ".local/bin/claude", "2.1.120", "only installed version", true),
	}

	out := render(Style{Width: 160}, v)

	// The installs get their own line, so they're never cut off.
	if want := ".claude  1 project (1 trusted)\n|              2.1.120 native, on PATH - +1 install\n"; !strings.Contains(out, want) {
		t.Errorf("output =\n%s\nwant %q", out, want)
	}
}

func TestANewerAgentThanTheToolListIsNoted(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.Agents[0].Installs = []model.Install{f.install(model.AgentClaude, model.InstallNPM, "npm/claude", "9.0.0", "package.json", true)}

	out := render(Style{Width: 160}, v)

	if want := "9.0.0 npm, on PATH - newer than jarx's tool list\n"; !strings.Contains(out, want) {
		t.Errorf("output =\n%s\nwant %q", out, want)
	}
}

func TestAnUnknownVersionSaysSo(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.Agents[0].Installs = []model.Install{f.install(model.AgentClaude, model.InstallNative, ".local/bin/claude", "", "2 versions", false)}

	if out := render(Style{Width: 160}, v); !strings.Contains(out, "|              version unknown native\n") {
		t.Errorf("output =\n%s\nwant the version marked unknown", out)
	}
}

func TestAnInstalledAgentWithNoConfigIsntNotFound(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.Agents[1].Installs = []model.Install{f.install(model.AgentCodex, model.InstallNPM, "npm/codex", "0.38.0", "package.json", true)}

	out := render(Style{Width: 160}, v)

	if want := "no config dir - 0.38.0 npm, on PATH\n"; !strings.Contains(out, want) {
		t.Errorf("output =\n%s\nwant %q", out, want)
	}
}

func TestTheInventoryListsEveryInstall(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.All = true
	v.Agents[0].Installs = []model.Install{
		f.install(model.AgentClaude, model.InstallNative, ".local/bin/claude", "2.1.120", "only installed version", true),
		f.install(model.AgentClaude, model.InstallNPM, "npm/claude", "", "package.json has no version", false),
	}

	out := render(Style{Width: 200}, v)

	sep := string(filepath.Separator)
	want := "installs (2)\n" +
		"  claude  native  2.1.120  ~" + sep + ".local" + sep + "bin" + sep + "claude  only installed version  on PATH\n" +
		"  claude  npm  version unknown  ~" + sep + "npm" + sep + "claude  package.json has no version\n"
	if !strings.Contains(out, want) {
		t.Errorf("output =\n%s\nwant %q", out, want)
	}
}
