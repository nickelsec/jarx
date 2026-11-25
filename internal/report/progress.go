package report

import (
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Progress is the one line that says what a long command is doing, redrawn
// in place on stderr and erased before the report prints. It only draws
// when stderr is a terminal, and it only ever shows jarx's own step names
// and counts, never a path or anything from a file. Its methods are safe
// from several goroutines, and on a nil Progress they do nothing.
type Progress struct {
	mu    sync.Mutex
	w     io.Writer
	st    Style
	now   func() time.Time
	start time.Time
	width int // the longest step name, so counts start in one column

	step                   string
	total, done, run, wait int
	bar                    bool
	frame                  int
	drawn                  int // the widest line drawn so far, for Stop to blank
	stopped                bool
	quit, idle             chan struct{}
}

// Progress layout, in columns, and how often the spinner turns.
const (
	barCells    = 20
	narrowBar   = 10 // on terminals under narrowWidth columns
	narrowWidth = 60
	tick        = 100 * time.Millisecond
)

// The spinner's frames.
const (
	spinUnicode = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
	spinASCII   = `|/-\`
)

// StartProgress starts the progress line for a command whose steps are
// named up front, so their counts line up. When stderr isn't a terminal it
// returns a Progress that draws nothing.
func (p *Printer) StartProgress(steps ...string) *Progress {
	g := newProgress(p.Err.w, p.ErrStyle, steps, time.Now)
	if !p.Live {
		g.stopped = true
		return g
	}
	g.quit, g.idle = make(chan struct{}), make(chan struct{})
	go g.spin()
	return g
}

func newProgress(w io.Writer, st Style, steps []string, now func() time.Time) *Progress {
	g := &Progress{w: w, st: st, now: now, start: now()}
	for _, s := range steps {
		g.width = max(g.width, cells(s))
	}
	return g
}

// Step moves to a step with no count.
func (g *Progress) Step(name string) { g.set(name, 0, false) }

// Count moves to a step with a count of total.
func (g *Progress) Count(name string, total int) { g.set(name, total, false) }

// Bar moves to a step shown as a bar.
func (g *Progress) Bar(name string, total int) { g.set(name, total, true) }

// Set says how many are done and how many are running now.
func (g *Progress) Set(done, running int) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.done, g.run = done, running
}

// Waiting says how many of the running ones are waiting, like out a rate
// limit.
func (g *Progress) Waiting(n int) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.wait = n
}

// Stop blanks the line and stops drawing. It's safe to call twice.
func (g *Progress) Stop() {
	if g == nil {
		return
	}
	g.mu.Lock()
	if g.stopped {
		g.mu.Unlock()
		return
	}
	g.stopped = true
	if g.drawn > 0 {
		_, _ = io.WriteString(g.w, "\r"+strings.Repeat(" ", g.drawn)+"\r")
	}
	g.mu.Unlock()
	if g.quit != nil {
		close(g.quit)
		<-g.idle
	}
}

// spin redraws the line until Stop.
func (g *Progress) spin() {
	defer close(g.idle)
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-g.quit:
			return
		case <-t.C:
			g.mu.Lock()
			g.turn()
			g.drawLocked()
			g.mu.Unlock()
		}
	}
}

func (g *Progress) set(name string, total int, bar bool) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.step, g.total, g.bar, g.done, g.run, g.wait = name, total, bar, 0, 0, 0
	g.drawLocked()
}

func (g *Progress) turn() { g.frame++ }

func (g *Progress) draw() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.drawLocked()
}

// drawLocked writes the line over the last one. Spaces blank whatever was
// longer before. Colors are only jarx's own tones.
func (g *Progress) drawLocked() {
	if g.stopped || g.step == "" {
		return
	}
	l := g.line()
	n := l.cells()
	var b strings.Builder
	b.WriteString("\r")
	for _, s := range l {
		if g.st.Color && s.tone != plain && s.text != "" {
			b.WriteString(s.tone.code() + s.text + reset)
			continue
		}
		b.WriteString(s.text)
	}
	if n < g.drawn {
		b.WriteString(strings.Repeat(" ", g.drawn-n))
	}
	g.drawn = max(g.drawn, n)
	_, _ = io.WriteString(g.w, b.String())
}

// render is the line as plain text, for tests.
func (g *Progress) render() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.line().plain()
}

// line is the spinner, the step padded to the longest name, the count or
// bar, and the time so far, cut one column short of the width so the line
// never wraps.
func (g *Progress) line() line {
	spin := []rune(spinASCII)
	if g.st.Unicode {
		spin = []rune(spinUnicode)
	}
	l := line{{text: string(spin[g.frame%len(spin)]), tone: cyan}, {text: " "}}
	switch {
	case g.bar:
		l = append(l, seg{text: own(pad(g.step, g.width))}, seg{text: "  "})
		l = append(l, g.barSegs()...)
		l = append(l, seg{text: "  " + g.count()})
		l = append(l, g.busy()...)
	case g.total > 0:
		l = append(l, seg{text: own(pad(g.step, g.width))}, seg{text: "  " + g.count()})
		l = append(l, g.busy()...)
	default:
		l = append(l, seg{text: own(g.step)})
	}
	if took := g.now().Sub(g.start); took >= time.Second {
		l = append(l, seg{text: wideGap}, seg{text: elapsed(took), tone: dim})
	}
	return trimLine(g.st.fit(l, g.st.width()-1))
}

// busy is how many are running and waiting, when any are.
func (g *Progress) busy() line {
	var l line
	if g.run > 0 {
		l = append(l, seg{text: own(g.sep() + strconv.Itoa(g.run) + " running")})
	}
	if g.wait > 0 {
		l = append(l, seg{text: own(g.sep() + strconv.Itoa(g.wait) + " waiting"), tone: yellow})
	}
	return l
}

func (g *Progress) sep() string { return " " + g.st.glyphs().dot + " " }

// count is "done of total", with done padded to total's width so the line
// doesn't move as it goes up.
func (g *Progress) count() string {
	t := strconv.Itoa(g.total)
	d := strconv.Itoa(min(g.done, g.total))
	return strings.Repeat(" ", len(t)-len(d)) + d + " of " + t
}

func (g *Progress) barSegs() line {
	size := barCells
	if g.st.width() < narrowWidth {
		size = narrowBar
	}
	filled := 0
	if g.total > 0 {
		filled = min(g.done, g.total) * size / g.total
	}
	full, empty := "#", "-"
	if g.st.Unicode {
		full, empty = "█", "░"
	}
	return line{
		{text: "["},
		{text: strings.Repeat(full, filled), tone: cyan},
		{text: strings.Repeat(empty, size-filled), tone: dim},
		{text: "]"},
	}
}

// elapsed is a short time so far: 12s, or 1m 05s.
func elapsed(d time.Duration) string {
	s := int(d / time.Second)
	if s < 60 { //nolint:mnd // seconds in a minute
		return strconv.Itoa(s) + "s"
	}
	sec := strconv.Itoa(s % 60) //nolint:mnd // seconds in a minute
	if len(sec) == 1 {
		sec = "0" + sec
	}
	return strconv.Itoa(s/60) + "m " + sec + "s" //nolint:mnd // seconds in a minute
}

// trimLine drops trailing spaces from the last segment, so a padded name
// with nothing after it doesn't leave a tail.
func trimLine(l line) line {
	if len(l) == 0 {
		return l
	}
	last := l[len(l)-1]
	last.text = strings.TrimRight(last.text, " ")
	return append(l[:len(l)-1:len(l)-1], last)
}
