package report

import (
	"strings"

	"github.com/nickelsec/jarx/internal/redact"
)

// bannerRows is the jarx wordmark: heavy pixel letters after the logo, nine
// rows by 43 columns, so it fits a 60-column terminal.
//
//nolint:gochecknoglobals // fixed art, read only
var bannerRows = []string{
	"    █████     ████    ████████   ███    ███",
	"    █████    ██████   █████████  ████  ████",
	"    █████   ███  ███  ███   ████  ████████",
	"    █████   ███  ███  ███   ████   ██████",
	"    █████  ███    ███ █████████     ████",
	"    █████  ██████████ ████████     ██████",
	"██  █████  ███    ███ ███ ████    ████████",
	"█████████  ███    ███ ███  ████  ████  ████",
	" ███████   ███    ███ ███   ████ ███    ███",
}

// tagline goes under the banner.
const tagline = "what your coding agents can see and reach"

// Banner prints the wordmark with the version next to its last row, then
// the tagline. Every run starts with it. It's ASCII wherever the tree is:
// piped output and consoles that can't show block characters.
func (p *Printer) Banner(version redact.Text) {
	ver := seg{text: escape(version.String())}
	for i, row := range bannerRows {
		if !p.Style.Unicode {
			row = strings.ReplaceAll(row, "█", "#")
		}
		l := line{{text: row, tone: bold}}
		if i == len(bannerRows)-1 && cells(row)+minGap+cells(ver.text) <= p.Style.width() {
			l = append(l, seg{text: "  "}, ver)
			ver.text = ""
		}
		p.emit(l)
	}
	// A version too long to sit next to the banner gets its own line, so
	// it's never cut.
	if ver.text != "" {
		_, _ = p.Out.w.Write([]byte(ver.text + "\n"))
	}
	p.blank()
	p.emit(line{{text: tagline, tone: dim}})
	p.blank()
}
