package history

import (
	"bufio"
	"io"

	"github.com/klauspost/compress/zstd"
)

// maxDecoded caps how much a compressed rollout may expand to, so a small
// file can't make jarx read without end.
const maxDecoded = 1 << 30

// maxWindow caps the decoder's window, which bounds its memory.
const maxWindow = 64 << 20

// readCompressed reads a .zst rollout. A compressed stream can't be read
// from an offset, but Codex compresses a rollout once its session is done,
// so jarx reads it whole when it's new or changed and keeps the results
// otherwise. A file that doesn't decode is skipped, never an error.
func (r *reader) readCompressed(path string, st *fileState, fn func(line []byte, n int)) {
	r.files = append(r.files, path)
	r.res.Files++
	info, err := r.c.Files.Stat(path)
	if err != nil {
		return
	}
	if info.Size() > maxFileSize {
		*st = fileState{}
		r.res.Findings = append(r.res.Findings, TooLarge().New(r.origin(path, 0), r.text("over 200 MB, so it wasn't read")))
		return
	}
	f, closeFile, ok := open(r.c, path)
	if !ok {
		return
	}
	defer closeFile()
	if st.Size == info.Size() && st.ModTime.Equal(info.ModTime()) && st.HeadLen > 0 && hashAt(f, st.HeadLen) == st.Head {
		return // unchanged since the last scan
	}
	*st = fileState{}
	dec, err := zstd.NewReader(f, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxWindow(maxWindow), zstd.WithDecoderMaxMemory(maxDecoded))
	if err != nil {
		return
	}
	defer dec.Close()
	got := readLines(st, bufio.NewReaderSize(io.LimitReader(dec, maxDecoded), readBuffer), fn)
	r.res.Read += got.lines
	// The cursor tracks the compressed file, not the stream inside it.
	st.Size, st.ModTime, st.Offset = info.Size(), info.ModTime(), info.Size()
	st.HeadLen = int(min(info.Size(), headSize))
	st.Head = hashAt(f, st.HeadLen)
}
