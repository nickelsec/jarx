// Command gendemo writes the demo home's binary history fixtures: a
// compressed Codex rollout and Codex's state and memories databases. They
// can't be written by hand, so this keeps them rebuildable. Run it from the
// repo root:
//
//	go run ./testdata/gendemo
//
// Shapes are observed, not documented (boughs docs/format-codex.md, and
// table and column names only from a real CODEX_HOME). Everything in them
// is made up.
package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
	_ "modernc.org/sqlite"
)

const codex = "testdata/demo/.codex"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gendemo:", err)
		os.Exit(1)
	}
}

func run() error {
	if err := compressed(); err != nil {
		return err
	}
	if err := database("state_5.sqlite",
		`create table threads (id text primary key, rollout_path text, cwd text, approval_mode text, sandbox_policy text, updated_at_ms integer, title text)`,
		// The app session from the plain rollout: same id, so it merges.
		`insert into threads values ('demo0004-0000-4000-8000-000000000004', '', '/projects/app', 'never', '{"type":"danger-full-access"}', 1795341600000, 'ship it')`,
		// One that's only in the database. Planted: run with no approvals, like
		// the auto-reviewed rollout, so the notes project's needs approval
		// verdicts show as effectively readable.
		`insert into threads values ('demo0006-0000-4000-8000-000000000006', '', '/projects/notes', 'never', '{"type":"workspace-write"}', 1795251600000, 'tidy notes')`,
	); err != nil {
		return err
	}
	return database("memories_1.sqlite",
		`create table stage1_outputs (thread_id text, source_updated_at integer, raw_memory text, rollout_summary text, rollout_slug text, generated_at integer)`,
		`insert into stage1_outputs values ('demo0004-0000-4000-8000-000000000004', 0, 'the user deploys with make ship', 'shipped the app', 'ship', 0)`,
		// Planted: a raw memory that kept a token. jarx shows its row and type, masked.
		`insert into stage1_outputs values ('demo0005-0000-4000-8000-000000000005', 0, 'the notes sync uses SYNC_TOKEN=demoCodexMem3Jw8Rt5Ky1Pq6Zn-fake', 'set up sync', 'sync', 0)`,
	)
}

// compressed writes an older, finished rollout as .jsonl.zst, the way Codex
// keeps them.
func compressed() error {
	id := "demo0005-0000-4000-8000-000000000005"
	lines := `{"timestamp":"2026-11-20T08:00:00.000Z","ordinal":0,"type":"session_meta","payload":{"id":"` + id + `","session_id":"` + id + `","cwd":"/projects/notes","timestamp":"2026-11-20T08:00:00.000Z"}}
{"timestamp":"2026-11-20T08:00:01.000Z","ordinal":1,"type":"turn_context","payload":{"approval_policy":"on-request","approvals_reviewer":"auto_review","sandbox_policy":{"type":"workspace-write","network_access":false}}}
{"timestamp":"2026-11-20T08:00:02.000Z","ordinal":2,"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"set up the notes sync"}]}}
`
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf)
	if err != nil {
		return err
	}
	if _, err := enc.Write([]byte(lines)); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	path := filepath.Join(codex, "sessions", "2026", "11", "20", "rollout-2026-11-20T08-00-00-"+id+".jsonl.zst")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}

func database(name string, stmts ...string) error {
	path := filepath.Join(codex, name)
	_ = os.Remove(path)
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}
