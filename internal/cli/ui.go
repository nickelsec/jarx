package cli

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nickelsec/jarx/internal/jarxdir"
	"github.com/nickelsec/jarx/internal/llm"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
	"github.com/nickelsec/jarx/internal/report"
	"github.com/nickelsec/jarx/internal/snapshot"
	"github.com/nickelsec/jarx/internal/ui"
)

const uiUsage = `usage: jarx ui [--home <dir>]

Starts the dashboard on 127.0.0.1, on a random port, and prints a link
with a one-time token. Ctrl+C stops it.

flags:
  --home <dir>  use <dir> as the home dir instead of the real one
  -h, --help    show this help
`

func uiHelp(s *report.Stream) { s.Printf(uiUsage) }

// shutdownWait is how long the dashboard has to finish answering after
// ctrl+c.
const shutdownWait = 5 * time.Second

func runUI(p *report.Printer, plain *redact.Scrubber, args []string, st streams) int {
	fs := newFlagSet("ui")
	home := fs.String("home", "", "")
	if code, ok := parse(p, plain, fs, args, uiHelp); !ok {
		return code
	}
	if emptyHome(fs, *home) {
		return usageError(p, uiHelp, scrubbed(plain, "--home needs a directory"))
	}
	if fs.NArg() > 0 {
		return usageError(p, uiHelp, scrubbed(plain, "jarx ui takes no arguments"))
	}
	ss, ok := openScan(p, scanFlags{home: *home}, st)
	if !ok {
		return exitError
	}
	defer func() { _ = ss.files.Close() }()
	app, err := newUIApp(p, ss, st)
	if err != nil {
		p.Error(err)
		return exitError
	}

	l, err := ui.Listen(0)
	if err != nil {
		p.Error(err)
		return exitError
	}
	port := l.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert // ui.Listen listens on TCP
	token := ui.NewToken()
	server := ui.NewServer(ui.Protect(ui.Pages(app), token, port))

	return serveUI(p, plain, st, l, server, "http://127.0.0.1:"+strconv.Itoa(port)+"/?t="+token)
}

// serveUI serves until ctrl+c, after printing the link whole.
func serveUI(p *report.Printer, plain *redact.Scrubber, st streams, l net.Listener, server *http.Server, link string) int {
	notify := st.interrupt
	if notify == nil {
		notify = catchInterrupt
	}
	sig, stop := notify()
	defer stop()
	served := make(chan error, 1)
	go func() { served <- server.Serve(l) }()

	p.Intro(scrubbed(plain, "jarx dashboard"), []redact.Text{
		scrubbed(plain, "127.0.0.1 only"+p.Sep()+"the link works once"),
		scrubbed(plain, "ctrl+c stops it"),
	})
	p.Blank()
	// The link is printed whole, never cut, so it can be copied.
	p.Out.Printf("  %s\n", scrubbed(plain, link))
	p.Blank()

	select {
	case <-sig:
	case err := <-served:
		if !errors.Is(err, http.ErrServerClosed) {
			p.Error(err)
			return exitError
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownWait)
	defer cancel()
	_ = server.Shutdown(ctx)
	p.Say(scrubbed(plain, "dashboard stopped"))
	return exitOK
}

// uiData scans the way jarx scan does, saves the snapshot, and adds the
// LLM review's settings and checklist. The key's var is looked up in the
// terminal's env, and only whether it's set goes on the page.
func uiData(p *report.Printer, ss scanSetup, st streams) (ui.Data, error) {
	sc, err := scanOnce(p, ss, scanFlags{})
	if err != nil {
		return ui.Data{}, err
	}
	saveScan(ss, &sc)
	s := ss.scrub
	d := ui.Data{
		Scan: sc.view, Scanned: time.Now(), Version: strings.TrimPrefix(st.userAgent, "jarx/"),
		StateDir: scrubbed(s, ss.env.StateDir),
	}
	d.History, d.HistoryNote = runLog(ss.env)
	d.Snapshots = olderSnapshots(ss.env)
	for _, r := range ss.cfg.Repos {
		d.Repos = append(d.Repos, scrubbed(s, r))
	}
	if c := ss.cfg.LLM; c != nil {
		ep := llm.Endpoint{BaseURL: c.BaseURL, Model: c.Model}
		arts := llm.Collect(s, sc.res.Projects)
		cache := llm.LoadCache(ss.env)
		_, set := llm.KeyFrom(st.lookupKey, c.KeyEnv)
		d.LLM = ui.LLM{
			On: true, BaseURL: scrubbed(s, c.BaseURL), Model: scrubbed(s, c.Model), KeyEnv: scrubbed(s, c.KeyEnv),
			KeySet: set, Parallel: parallelOf(*c),
			Artifacts: arts, States: llm.States(ep, arts, cache), Plan: llm.Plan(ep, arts, cache),
		}
	}
	return d, nil
}

// runLog reads the scan history the scans keep in the state dir.
func runLog(env platform.Env) (snapshot.RunLog, string) {
	d, err := jarxdir.Open(env)
	if err != nil {
		return snapshot.RunLog{}, "couldn't open jarx's state dir"
	}
	defer func() { _ = d.Close() }()
	return snapshot.Runs(d)
}
