// Package cli parses jarx's command line and runs the commands. All output
// goes through report, and every value it prints goes through redact first.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"

	"github.com/nickelsec/jarx/internal/catalog"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
	"github.com/nickelsec/jarx/internal/report"
)

const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

const usage = `usage: jarx [--version] <command>

commands:
  scan   map what the agents can see and reach
  setup  show jarx's own settings, or add and remove extra repos
  ui     open the dashboard on 127.0.0.1

flags:
  --version   print the jarx version
  -h, --help  show this help
`

// helpFunc prints a command's help to the given stream.
type helpFunc func(*report.Stream)

func mainHelp(s *report.Stream) { s.Printf(usage) }

// streams are where a run reads and writes. interactive says a person is
// there to answer questions: both stdin and stdout are terminals.
// interrupt catches ctrl+c while jarx asks questions; nil means the real
// signal, and tests pass their own.
type streams struct {
	in          io.Reader
	out, err    io.Writer
	interactive bool
	interrupt   func() (<-chan os.Signal, func())
	lookupKey   keyLookup // the terminal's env, where the LLM key is; nil means no key
	userAgent   string    // jarx/<version>, what jarx calls itself to the LLM endpoint
	errLive     bool      // stderr is a terminal, so the progress line can draw there
}

// keyLookup reads one env var from the terminal jarx runs in. It's how the
// LLM key is read, even with --home, since the key is set in the terminal
// and never in a file.
type keyLookup func(string) (string, bool)

// catchInterrupt catches ctrl+c until stop is called, so a command that's
// asking questions can say what it did and didn't save.
func catchInterrupt() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	return ch, func() { signal.Stop(ch) }
}

// Run runs jarx with args (without the program name) and returns the exit
// code. ldflagsVersion is the version set at build time, or "".
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer, ldflagsVersion string) int {
	interactive := platform.DetectTerm(stdout).TTY && platform.IsTerminal(stdin)
	errLive := platform.DetectTerm(stderr).TTY
	return runWith(args, streams{in: stdin, out: stdout, err: stderr, interactive: interactive, lookupKey: platform.LookupReal, errLive: errLive}, ldflagsVersion)
}

func runWith(args []string, st streams, ldflagsVersion string) int {
	// No patterns until the catalog lands in phase 3, and no fingerprint key:
	// this scrubber only masks error text and wraps values as Text. New can
	// only fail on bad patterns, and there are none.
	plain, err := redact.New(nil, nil)
	if err != nil {
		panic("redact.New with no patterns failed: " + err.Error())
	}
	p := report.New(st.out, st.err, plain)
	t := platform.DetectTerm(st.out)
	p.Style = report.Style{Width: t.Width, Color: t.Color, Unicode: t.Unicode}
	et := platform.DetectTerm(st.err)
	p.ErrStyle = report.Style{Width: et.Width, Color: et.Color, Unicode: et.Unicode}
	p.Live = st.errLive
	info, _ := debug.ReadBuildInfo() // nil when not available
	version := versionFrom(ldflagsVersion, info)
	st.userAgent = "jarx/" + version
	// Every run starts with the banner, which has the version.
	p.Banner(scrubbed(plain, version))

	fs := newFlagSet("jarx")
	showVersion := fs.Bool("version", false, "")
	if code, ok := parse(p, plain, fs, args, mainHelp); !ok {
		return code
	}
	if *showVersion {
		p.Out.Printf("advisory data as of %s\n", scrubbed(plain, catalog.AdvisoriesStamp()))
		return exitOK
	}

	rest := fs.Args()
	if len(rest) == 0 {
		mainHelp(p.Err)
		return exitUsage
	}
	switch rest[0] {
	case "scan":
		return runScan(p, plain, rest[1:], st)
	case "setup":
		return runSetup(p, plain, rest[1:], st)
	case "ui":
		return runUI(p, plain, rest[1:], st)
	default:
		return usageError(p, mainHelp, scrubbed(plain, fmt.Sprintf("unknown command %q", rest[0])))
	}
}

// scrubbed runs raw through s and drops the finds.
func scrubbed(s *redact.Scrubber, raw string) redact.Text {
	t, _ := s.Scrub(raw)
	return t
}

// newFlagSet returns a flag set that reports nothing itself, so parse decides
// where help and errors go.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return fs
}

// parse parses args into fs. Help goes to stdout with exit 0, and a bad flag
// goes to stderr with exit 2. It returns the exit code and whether the caller
// should keep going; when that's false, the caller returns the code.
func parse(p *report.Printer, s *redact.Scrubber, fs *flag.FlagSet, args []string, help helpFunc) (int, bool) {
	err := fs.Parse(args)
	switch {
	case err == nil:
		return exitOK, true
	case errors.Is(err, flag.ErrHelp):
		help(p.Out)
		return exitOK, false
	default:
		return usageError(p, help, scrubbed(s, err.Error())), false
	}
}

func usageError(p *report.Printer, help helpFunc, msg redact.Text) int {
	p.Err.Printf("jarx: %s\n\n", msg)
	help(p.Err)
	return exitUsage
}

// versionFrom picks the ldflags version, then the module version that
// go install records, then "dev".
func versionFrom(ldflags string, info *debug.BuildInfo) string {
	if ldflags != "" {
		return ldflags
	}
	if info != nil && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}
