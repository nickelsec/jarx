package cli

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/nickelsec/jarx/internal/redact"
	"github.com/nickelsec/jarx/internal/report"
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
	_, files, _, err := openEnv(*home)
	if err != nil {
		p.Error(err)
		return exitError
	}
	defer func() { _ = files.Close() }()

	l, err := ui.Listen(0)
	if err != nil {
		p.Error(err)
		return exitError
	}
	port := l.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert // ui.Listen listens on TCP
	token := ui.NewToken()
	server := ui.NewServer(ui.Protect(placeholder(), token, port))

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

// placeholder is the dashboard until its pages land.
func placeholder() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("jarx dashboard\n"))
	})
}
