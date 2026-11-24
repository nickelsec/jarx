package history

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// dbTimeout bounds every database read. A locked file gets the short busy
// timeout below and is skipped; this is the backstop.
const dbTimeout = 5 * time.Second

// busyMillis is how long jarx waits on another process's lock.
const busyMillis = 200

// maxRows caps how many rows one table gives.
const maxRows = 10000

// dsnFor opens path read-only in place (prd.md, "Session history"):
// mode=ro so SQLite never writes it, query_only so no statement can, and a
// short busy timeout so a lock means a skip, not a wait. The path goes in
// as a file: URL so spaces, # and Windows drive letters arrive intact.
func dsnFor(path string) string {
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // C:/x becomes /C:/x, which SQLite reads as the drive
	}
	u := url.URL{Scheme: "file", Path: p}
	q := url.Values{}
	q.Set("mode", "ro")
	q.Add("_pragma", "query_only(1)")
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busyMillis))
	u.RawQuery = q.Encode()
	return u.String()
}

// databases reads the state and memories databases in dir: the newest
// version of each name that's there, since the number changes with the
// schema.
func (r *reader) databases(dir string) {
	entries, _ := r.c.Files.ReadDir(dir)
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || filepath.Ext(name) != ".sqlite" {
			continue
		}
		path := filepath.Join(dir, name)
		switch {
		case strings.HasPrefix(name, "state_"):
			r.withDB(path, r.threads)
		case strings.HasPrefix(name, "memories_"):
			r.withDB(path, r.memoryRows)
		}
	}
}

// withDB opens path read-only through fsys's checks and runs fn. A file
// that isn't a database, or has another shape, gives nothing. A locked one
// is an info finding.
func (r *reader) withDB(path string, fn func(ctx context.Context, db *sql.DB, st *fileState) error) {
	final, err := r.c.Files.DBPath(path)
	if err != nil {
		return
	}
	db, err := sql.Open("sqlite", dsnFor(final))
	if err != nil {
		return
	}
	defer func() { _ = db.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	st := &fileState{}
	r.files = append(r.files, path)
	r.res.Files++
	r.dbs[path] = st
	if err := fn(ctx, db, st); locked(err) {
		r.res.Findings = append(r.res.Findings, Locked().New(r.origin(path, 0), r.text("locked by another process, skipped this scan")))
	}
}

// primaryCode masks an extended SQLite result code down to its primary one.
const primaryCode = 0xff

func locked(err error) bool {
	if se, ok := errors.AsType[*sqlite.Error](err); ok {
		code := se.Code() & primaryCode
		return code == sqlite3.SQLITE_BUSY || code == sqlite3.SQLITE_LOCKED
	}
	return false
}

// columns are the table's column names, or none when it isn't there.
func columns(ctx context.Context, db *sql.DB, table string) ([]string, error) {
	rows, err := db.QueryContext(ctx, `select name from pragma_table_info(?)`, table)
	if err != nil {
		return nil, err //nolint:wrapcheck // only checked for a lock
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var name string
		if rows.Scan(&name) == nil {
			out = append(out, name)
		}
	}
	return out, rows.Err() //nolint:wrapcheck // only checked for a lock
}

// present are the wanted columns the table has, in want's order.
func present(ctx context.Context, db *sql.DB, table string, want []string) ([]string, error) {
	have, err := columns(ctx, db, table)
	if err != nil {
		return nil, err
	}
	var cols []string
	for _, c := range want {
		if slices.Contains(have, c) {
			cols = append(cols, c)
		}
	}
	return cols, nil
}

// selectText runs a select of the wanted columns that exist, each read as
// text (NULL is ""), and calls fn per row with them by name.
func selectText(ctx context.Context, db *sql.DB, table string, want []string, fn func(row map[string]string, n int)) error {
	cols, err := present(ctx, db, table, want)
	if err != nil || len(cols) == 0 {
		return err
	}
	quoted := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = `coalesce(cast("` + c + `" as text), '')`
	}
	// The table and column names are jarx's own constants, checked against
	// the file's schema; only the row limit is a parameter.
	query := `select ` + strings.Join(quoted, ", ") + ` from "` + table + `" limit ?` //nolint:gosec // G202: names are constants, not input
	rows, err := db.QueryContext(ctx, query, maxRows)
	if err != nil {
		return err //nolint:wrapcheck // only checked for a lock
	}
	defer func() { _ = rows.Close() }()
	vals := make([]string, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for n := 1; rows.Next(); n++ {
		if rows.Scan(ptrs...) != nil {
			continue
		}
		row := make(map[string]string, len(cols))
		for i, c := range cols {
			row[c] = vals[i]
		}
		fn(row, n)
	}
	return rows.Err() //nolint:wrapcheck // only checked for a lock
}

// threads adds a session per row of the state DB's threads table.
func (r *reader) threads(ctx context.Context, db *sql.DB, st *fileState) error {
	return selectText(ctx, db, "threads", []string{"id", "cwd", "approval_mode", "sandbox_policy", "updated_at_ms", "updated_at"},
		func(row map[string]string, _ int) {
			if !idRe.MatchString(row["id"]) {
				return
			}
			s := st.session(row["id"], row["id"])
			s.CWD = upperDrive(row["cwd"])
			if mode := approvalMode(row["approval_mode"]); mode != "" {
				s.Modes = append(s.Modes, "approval_policy="+mode)
			}
			if sb := sandboxType(json.RawMessage(row["sandbox_policy"])); modeValueRe.MatchString(sb) {
				s.Modes = append(s.Modes, "sandbox="+sb)
			}
			s.Last = rowTime(row["updated_at_ms"], row["updated_at"])
		})
}

// approvalMode is a thread's approval mode: a plain value, or granular when
// it's the granular object.
func approvalMode(v string) string {
	if modeValueRe.MatchString(v) {
		return v
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal([]byte(v), &obj) == nil && obj["granular"] != nil {
		return "granular"
	}
	return ""
}

// rowTime reads a millisecond timestamp, else seconds. Zero means undated.
func rowTime(ms, secs string) time.Time {
	var n int64
	if _, err := fmt.Sscan(ms, &n); err == nil && n > 0 {
		return time.UnixMilli(n).UTC()
	}
	if _, err := fmt.Sscan(secs, &n); err == nil && n > 0 {
		return time.Unix(n, 0).UTC()
	}
	return time.Time{}
}

// memoryRows checks the memories DB's raw memories for leaks, by row.
func (r *reader) memoryRows(ctx context.Context, db *sql.DB, st *fileState) error {
	return selectText(ctx, db, "stage1_outputs", []string{"raw_memory", "rollout_summary"}, func(row map[string]string, n int) {
		for _, text := range []string{row["raw_memory"], row["rollout_summary"]} {
			r.leaksAt(st, []byte(text), n, true)
		}
	})
}
