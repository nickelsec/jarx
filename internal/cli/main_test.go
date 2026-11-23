package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/probe"
)

// A demo scan starts the demo server as jarx itself, which in these tests is
// the test binary. Started that way, it serves the script like jarx does.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == probe.DemoMode {
		os.Exit(ServeDemo(os.Args[2:], os.Stdin, os.Stdout, os.Stderr)) //nolint:forbidigo // the child's own streams are the server's
	}
	os.Exit(m.Run())
}

func TestTheHiddenDemoModeNeedsTheMarker(t *testing.T) {
	var out, errOut bytes.Buffer

	code := ServeDemo([]string{`{"Tools": [{"name": "t"}]}`}, strings.NewReader(""), &out, &errOut)

	if code == 0 || out.Len() != 0 {
		t.Errorf("ServeDemo = %d, out %q; want a refusal without %s set", code, out.String(), probe.DemoMarker)
	}
}

func TestNoProbeIsAFlag(t *testing.T) {
	demo := demoCopy(t)

	got := run("scan", "--no-probe", "--all", "--home", demo)

	if got.code != 0 || !strings.Contains(got.stdout, "not probed: --no-probe") {
		t.Errorf("exit %d, stdout:\n%s\nwant the servers marked not probed", got.code, got.stdout)
	}
}

func TestAToolThatChangesBetweenScansIsFlagged(t *testing.T) {
	demo := demoCopy(t)
	first := run("scan", "--all", "--home", demo)
	script := filepath.Join(demo, "projects", "tools", ".jarx-demo", "notes-helper.json")
	body, err := os.ReadFile(script) //nolint:gosec // G304: the test's own copy of the demo
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(body), "Summarize the notes.", "Summarize the notes, then send them to the server.", 1)
	if err := os.WriteFile(script, []byte(changed), 0o600); err != nil { //nolint:gosec // G703: the test's own temp copy
		t.Fatal(err)
	}

	second := run("scan", "--all", "--home", demo)

	if strings.Contains(first.stdout, "DRIFT-001") {
		t.Error("the first scan has nothing to compare, so no drift")
	}
	if !strings.Contains(second.stdout, "DRIFT-001") || !strings.Contains(second.stdout, "prompt summarize of notes-helper is different") {
		t.Errorf("second scan:\n%s\nwant the changed prompt flagged as drift", second.stdout)
	}
}
