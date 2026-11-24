package history

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"github.com/nickelsec/jarx/internal/agent"
)

// maxFileSize is the largest history file read, 200 MB. A bigger one is
// skipped with an info finding (prd.md, "Session history"). A var so a test
// can lower it instead of writing 200 MB.
//
//nolint:gochecknoglobals // a constant, lowered only by a test
var maxFileSize int64 = 200 << 20

// maxLine is the longest line read. A longer one is counted and skipped:
// transcripts hold whole API requests on one line.
const maxLine = 16 << 20

// readBuffer is the line reader's buffer. Longer lines are read in pieces.
const readBuffer = 64 << 10

// readResult is what one file's read did.
type readResult struct {
	tooLarge  bool
	lines     int // new full lines read
	longLines int // new lines over maxLine, skipped
}

// seekFile is what reading from the cursor needs from an open file.
type seekFile interface {
	io.Reader
	io.ReaderAt
	io.Seeker
}

// readNew calls fn for each full line past the cursor, with its 1-based
// line number. A file that shrank or whose start changed is read from the
// start, and its earlier results are dropped. A last line with no newline
// yet is left for the next scan.
func readNew(c agent.Context, st *fileState, path string, fn func(line []byte, n int)) readResult {
	info, err := c.Files.Stat(path)
	if err != nil {
		return readResult{}
	}
	if info.Size() > maxFileSize {
		return readResult{tooLarge: true}
	}
	f, closeFile, ok := open(c, path)
	if !ok {
		return readResult{}
	}
	defer closeFile()
	if info.Size() < st.Offset || st.HeadLen > 0 && hashAt(f, st.HeadLen) != st.Head {
		*st = fileState{}
	}
	st.Size, st.ModTime = info.Size(), info.ModTime()
	if st.Offset == info.Size() {
		return readResult{}
	}
	if _, err := f.Seek(st.Offset, io.SeekStart); err != nil {
		return readResult{}
	}
	res := readLines(st, bufio.NewReaderSize(f, readBuffer), fn)
	if st.HeadLen < headSize {
		st.HeadLen = int(min(st.Offset, headSize))
		st.Head = hashAt(f, st.HeadLen)
	}
	return res
}

// open opens path for reading from an offset. Files from fsys always can.
func open(c agent.Context, path string) (seekFile, func(), bool) {
	rc, err := c.Files.Open(path)
	if err != nil {
		return nil, nil, false
	}
	f, ok := rc.(seekFile)
	if !ok {
		_ = rc.Close()
		return nil, nil, false
	}
	return f, func() { _ = rc.Close() }, true
}

// readLines reads full lines from br, moving the cursor past each.
func readLines(st *fileState, br *bufio.Reader, fn func(line []byte, n int)) readResult {
	var res readResult
	for {
		l, ok := readLine(br)
		if !ok {
			return res // EOF, maybe mid-line: that part waits for the next scan
		}
		st.Offset += int64(l.size)
		st.Lines++
		res.lines++
		if l.long {
			res.longLines++
			continue
		}
		fn(bytes.TrimRight(l.text, "\r\n"), st.Lines)
	}
}

// line is one line read: its text (empty when long), how many bytes it
// took, and whether it was over maxLine.
type line struct {
	text []byte
	size int
	long bool
}

// readLine reads up to and including a newline. A line over maxLine comes
// back long, after reading past it. ok is false when the input ends before
// a newline.
func readLine(br *bufio.Reader) (line, bool) {
	var l line
	for {
		chunk, err := br.ReadSlice('\n')
		l.size += len(chunk)
		if !l.long {
			if len(l.text)+len(chunk) > maxLine {
				l.long, l.text = true, nil
			} else {
				l.text = append(l.text, chunk...)
			}
		}
		switch {
		case err == nil:
			return l, true
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return line{}, false
		}
	}
}

func hashAt(r io.ReaderAt, n int) string {
	buf := make([]byte, n)
	if _, err := r.ReadAt(buf, 0); err != nil && !errors.Is(err, io.EOF) {
		return ""
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}
