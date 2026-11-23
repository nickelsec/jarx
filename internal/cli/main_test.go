package cli

import (
	"bytes"
	"os"
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
