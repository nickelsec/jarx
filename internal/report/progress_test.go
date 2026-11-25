package report

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// clock is a fake time that tests move by hand.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func testProgress(st Style, steps ...string) (*Progress, *bytes.Buffer, *clock) {
	var buf bytes.Buffer
	c := &clock{t: time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)}
	return newProgress(&buf, st, steps, c.now), &buf, c
}

func scanSteps() []string {
	return []string{"reading session history", "walking projects", "probing MCP servers", "checking findings"}
}

func TestProgressLinesUpEveryStep(t *testing.T) {
	g, _, c := testProgress(Style{Width: 80, Unicode: true}, scanSteps()...)

	g.Step("reading session history")
	history := g.render()
	g.Count("probing MCP servers", 17)
	g.Set(3, 4)
	c.t = c.t.Add(12 * time.Second)
	probing := g.render()
	g.Set(12, 4)
	later := g.render()

	if want := "⠋ reading session history"; history != want {
		t.Errorf("history = %q, want %q", history, want)
	}
	// The step names are padded to the longest, so counts start in one
	// column, and the count is padded to its total, so the time doesn't
	// move as it goes up.
	if want := "⠋ probing MCP servers       3 of 17 · 4 running   12s"; probing != want {
		t.Errorf("probing = %q, want %q", probing, want)
	}
	if want := "⠋ probing MCP servers      12 of 17 · 4 running   12s"; later != want {
		t.Errorf("later = %q, want %q", later, want)
	}
	if cells(probing) != cells(later) {
		t.Errorf("the line changed width as the count went up: %d then %d", cells(probing), cells(later))
	}
}

func TestProgressShowsMinutes(t *testing.T) {
	g, _, c := testProgress(Style{Width: 80}, "checking findings")

	g.Step("checking findings")
	c.t = c.t.Add(65 * time.Second)

	if got, want := g.render(), "| checking findings   1m 05s"; got != want {
		t.Errorf("render = %q, want %q", got, want)
	}
}

func TestProgressBarFillsAndLinesUp(t *testing.T) {
	g, _, c := testProgress(Style{Width: 80, Unicode: true}, "reviewing")

	g.Bar("reviewing", 14)
	g.Set(6, 0)
	c.t = c.t.Add(38 * time.Second)
	got := g.render()
	g.Set(14, 0)
	full := g.render()

	if want := "⠋ reviewing  [████████░░░░░░░░░░░░]   6 of 14   38s"; got != want {
		t.Errorf("render = %q, want %q", got, want)
	}
	if want := "⠋ reviewing  [████████████████████]  14 of 14   38s"; full != want {
		t.Errorf("full = %q, want %q", full, want)
	}
}

func TestProgressIsASCIIWhereTheTerminalIs(t *testing.T) {
	g, _, _ := testProgress(Style{Width: 80}, "reviewing", "probing MCP servers")

	g.Bar("reviewing", 4)
	g.Set(1, 0)
	bar := g.render()
	g.Count("probing MCP servers", 2)
	g.Set(1, 1)
	count := g.render()

	if want := "| reviewing            [#####---------------]  1 of 4"; bar != want {
		t.Errorf("bar = %q, want %q", bar, want)
	}
	if want := "| probing MCP servers  1 of 2 - 1 running"; count != want {
		t.Errorf("count = %q, want %q", count, want)
	}
}

func TestProgressSpinnerTurns(t *testing.T) {
	g, _, _ := testProgress(Style{Width: 80}, "x")
	g.Step("x")

	frames := make([]string, 0, 5)
	for range 5 {
		frames = append(frames, g.render()[:1])
		g.turn()
	}

	if got := strings.Join(frames, ""); got != `|/-\|` {
		t.Errorf("frames = %q, want |/-\\|", got)
	}
}

func TestProgressNeverWrapsANarrowTerminal(t *testing.T) {
	g, _, c := testProgress(Style{Width: 30, Unicode: true}, "probing MCP servers")
	g.Count("probing MCP servers", 170)
	g.Set(3, 4)
	c.t = c.t.Add(time.Minute)

	if got := g.render(); cells(got) > 29 {
		t.Errorf("render = %q is %d cells, want at most 29 so it never wraps", got, cells(got))
	}
}

func TestProgressDrawsInPlaceAndStopErasesIt(t *testing.T) {
	g, buf, _ := testProgress(Style{Width: 80}, "walking projects", "checking findings")

	g.Count("walking projects", 3)
	g.Set(1, 0)
	g.draw()
	g.Step("checking findings")
	g.draw()
	g.Stop()

	out := buf.String()
	if !strings.Contains(out, "\r| walking projects   1 of 3\r| checking findings") || strings.Contains(out, "\n") {
		t.Errorf("out = %q, want lines drawn over each other with \\r and no new line", out)
	}
	// Stop blanks the longest line drawn and leaves the cursor at the start.
	if !strings.HasSuffix(out, "\r"+strings.Repeat(" ", len("| walking projects   1 of 3"))+"\r") {
		t.Errorf("out = %q, want Stop to blank the line", out)
	}
	g.Stop() // twice is fine
	g.draw() // and nothing draws after
	if buf.String() != out {
		t.Errorf("wrote %q after Stop", strings.TrimPrefix(buf.String(), out))
	}
}

func TestProgressIsOffWithoutATerminal(t *testing.T) {
	var out, errw bytes.Buffer
	p := New(&out, &errw, nil)

	g := p.StartProgress("x")
	g.Step("x")
	g.Count("x", 3)
	g.Set(1, 0)
	g.Stop()

	if out.Len() != 0 || errw.Len() != 0 {
		t.Errorf("wrote %q and %q, want nothing when stderr isn't a terminal", out.String(), errw.String())
	}
}

func TestANilProgressDoesNothing(_ *testing.T) {
	var g *Progress
	g.Step("x")
	g.Count("x", 1)
	g.Bar("x", 1)
	g.Set(1, 0)
	g.Stop()
}

func TestProgressSaysWhatIsRunningAndWaiting(t *testing.T) {
	g, _, c := testProgress(Style{Width: 80, Unicode: true}, "reviewing")

	g.Bar("reviewing", 85)
	g.Set(14, 4)
	g.Waiting(1)
	c.t = c.t.Add(65 * time.Second)
	got := g.render()
	g.Waiting(0)
	none := g.render()

	if want := "⠋ reviewing  [███░░░░░░░░░░░░░░░░░]  14 of 85 · 4 running · 1 waiting   1m 05s"; got != want {
		t.Errorf("render = %q, want %q", got, want)
	}
	if cells(got) > 79 { // one short of 80
		t.Errorf("render is %d cells, want it to fit 80 columns", cells(got))
	}
	if strings.Contains(none, "waiting") {
		t.Errorf("render = %q, want no waiting once nothing waits", none)
	}
}
