# jarx design

Status: draft v1. Last updated 2026-11-22. Goes with [prd.md](prd.md).

Go is decided. This doc covers everything else: how the code is split up, how
data moves through a scan, how the PRD's promises are enforced, and the phases
it gets built in. [progress.md](progress.md) tracks where we are.

## Decisions from research

These came out of research and change or sharpen the PRD.

### Codex sqlite: open the original read-only

The PRD said `mode=ro&immutable=1`. The SQLite URI docs say that if a file
opened as immutable "changes anyhow, then SQLite might return incorrect query
results and/or SQLITE_CORRUPT errors", and immutable mode also skips the
`-wal` file. Codex writes these files while it runs, so immutable is wrong.

Copying the database and its WAL to temp was also rejected. It would put
history with secrets on disk, even for a moment, which breaks promise 3.

What jarx does:

- Opens the original with `mode=ro`, then sets `PRAGMA query_only = 1` and a
  short `busy_timeout` (2s).
- If the database is locked, or the open fails because the `-shm` file can't
  be used, jarx skips that file and adds an info finding ("Codex was busy, try
  again"). Partial data is never guessed at.
- jarx never writes, checkpoints or vacuums.

Source: https://www.sqlite.org/uri.html

### Probes never use a proxy

The dial-time IP block only works when jarx connects directly. Through a
proxy, the dialer only sees the proxy's address, and the proxy resolves the
target. So probe traffic ignores `HTTPS_PROXY` and friends. Behind a
corporate proxy, remote servers show as `unreachable`, and the "where your
agent talks to" panel says "proxy set, probes went direct".

Source: https://www.agwa.name/blog/post/preventing_server_side_request_forgery_in_golang

### Windows process trees: suspended start plus a job object

Calling `AssignProcessToJobObject` after `cmd.Start` is racy. The child can
spawn grandchildren before it's in the job (golang/go#79927). The fix for
that in `SysProcAttr` isn't in Go 1.25. jarx does this instead:

1. Create a job with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. The handle is not
   inheritable.
2. Start the server with `CREATE_SUSPENDED`.
3. Assign it to the job.
4. Resume it with `NtResumeProcess`.
5. On timeout or when done, close the job, which kills the whole tree.

On unix, the same thing is `Setpgid` plus `kill(-pgid, SIGKILL)`.

This makes `golang.org/x/sys/windows` a direct dependency. It was already an
indirect one through go-keyring and modernc sqlite.

Sources: https://github.com/golang/go/issues/79927,
https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects

### Hardened git for repo walks

A repo's own `.git/config` can point at commands (`core.fsmonitor`, diff
drivers). A clone doesn't carry config, but a repo that arrived as an archive
can. So jarx runs exactly:

```
git -c core.fsmonitor=false -c core.untrackedCache=false \
    ls-files -z --cached --others --exclude-standard
```

with `GIT_OPTIONAL_LOCKS=0` and a scrubbed env. It never touches
`safe.directory`. If git refuses or isn't installed, jarx uses its own walk.

### MCP client covers four protocol revisions

Revision 2026-07-28 removed protocol sessions and the GET stream from
Streamable HTTP. The client:

- offers every version it knows in `initialize` (2024-11-05 through
  2026-07-28)
- falls back to legacy SSE only when a POST gets `400`, `404` or `405`
  without a modern JSON-RPC error body (that's the spec's own rule)
- follows `nextCursor` on the list calls, up to 50 pages

Source: https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http

### Dashboard token goes into a cookie

`jarx ui` prints `http://127.0.0.1:<port>/?t=<token>`. The first request
trades the token for an `HttpOnly; SameSite=Strict` cookie and redirects with
303, so the token leaves the address bar and the browser history. Writes are
checked by Go 1.25's `http.CrossOriginProtection` (it uses `Sec-Fetch-Site`
and `Origin`). Every request also goes through a Host allowlist
(`127.0.0.1:<port>`, `localhost:<port>`) to stop DNS rebinding. A strict CSP
blocks inline script, and `frame-ancestors 'none'` stops framing.

Sources: https://www.calhoun.io/csrf-protection-via-headers-in-go-125,
https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/CSRF

## Guarantees enforced by structure

The PRD's promises shouldn't depend on everyone remembering them. Each one has
a spot in the code that makes breaking it hard.

| Promise | How the code makes breaking it hard |
|---|---|
| Secrets never leak | Model text fields are `redact.Text`. Only the `redact` package can build one (unexported field). `report`, `ui`, `snapshot` and `llm` only take `redact.Text`, so there's no way to put a raw string on screen, on disk or on the wire. Anything that matches a secret pattern is always masked. Entropy only flags a match as a likely placeholder, it never decides whether to mask, because showing a real secret is far worse than hiding a fake one. |
| Nothing raw reaches the terminal or a log | Only `report` writes output. `forbidigo` bans `fmt.Print*`, `fmt.Fprint*`, `os.Stdout`, `os.Stderr`, `print`, `println`, `log` and `log/slog` everywhere else (`cmd/jarx` may use `os.Stdout` and `os.Stderr` only to hand them to `report`). `report` takes values only as `redact.Text`, and its format string has an unexported type, so a string variable won't compile as the format. `report.Error` scrubs error text, since a parser error can quote the line it failed on. The limit: a package handed an `io.Writer` could still call `Write` on it, but only `cmd/jarx` can reach the real stdout and stderr, so that needs a new parameter that review would catch. |
| Never calls a tool | The `mcp` package has constants only for `initialize`, `notifications/initialized`, `tools/list`, `prompts/list` and `resources/list`. A `go/ast` test fails if any other method string shows up in the package. |
| Only the listed network calls | `netguard` is the only package allowed to build an `http.Client`, a transport or a dialer. golangci `forbidigo` bans `http.Get`, `http.DefaultClient`, `net.Dial*` and `http.Transport{` everywhere else. |
| Never writes agent config | `fsys` has no write methods. The only writer is `jarxdir`, which is rooted at jarx's state dir (`os.UserConfigDir()/jarx`, or `<home>/.jarx-state` with `--home`) with `os.Root`. `forbidigo` bans `os.WriteFile`, `os.Create`, `os.Mkdir*`, `os.Remove*`, `os.Rename` and friends everywhere else (tests may write fixtures). |
| Tests and demos never touch the real machine | Adapters take an injected `platform.Env` (home, GOOS, env, PATH, state dir, system roots). `forbidigo` bans `os.UserHomeDir`, `os.Getenv` and friends outside `platform`, and bans `os.Open`, `os.ReadFile`, `os.Stat`, `os.OpenRoot`, `filepath.Walk*` and friends outside `fsys`, `jarxdir` and `platform`. Under `--home`, `fsys` confines every read to the fake home with `os.Root`, so a fixture that points at a real path, a `..` trick or a symlink can't reach the real machine. `--home` builds a `platform.Env` with no system roots, registry, plists, real env or real PATH. |
| Only approved dependencies | golangci `depguard` lists the five approved modules plus stdlib. A new import fails lint until someone approves it. |

## Architecture

```mermaid
flowchart LR
  subgraph In[Inputs, read-only]
    FS[(config, instruction,<br/>memory, skill, hook files)]
    H[(session history<br/>jsonl / zst / sqlite ro)]
    MCP[[MCP servers<br/>stdio / http / sse]]
  end
  subgraph Adapters
    CA[agent/claude]
    XA[agent/codex]
  end
  D[discover<br/>projects + repo walk]
  R{{redact<br/>scrub + fingerprint}}
  M[(model.Inventory<br/>every value has an Origin)]
  P[probe<br/>proc + mcp + netguard]
  HI[history<br/>incremental cursor]
  subgraph Analyzers
    PO[poison] --- SE[secrets]
    RE[reach + credential view] --- CP[capability]
    PE[perms] --- EG[egress]
    DR[drift] --- VE[versions] --- UK[unknown keys]
  end
  F[(findings)]
  S[(snapshot store<br/>last 20 + diff)]
  L[llm, only with --llm]
  O1[report: CLI]
  O2[ui: 127.0.0.1]

  D --> CA & XA
  FS --> CA & XA
  CA & XA --> R --> M
  M --> P
  MCP <--> P
  P --> R
  H --> HI --> R
  M --> Analyzers --> F
  F --> L --> F
  F & M --> S
  S --> O1 & O2
```

Three layers, matching the PRD:

1. **Adapters** know one agent each: its paths, formats, precedence, trust
   rules and quirks. Nothing outside an adapter knows an agent's file layout.
2. **The model** is agent-neutral, and every value in it carries an `Origin`
   (file, scope, line where possible, and whether it's in effect, with a
   reason if not).
3. **Analyzers** only read the model. Adding an agent means writing an
   adapter. The analyzers stay the same.

The shape follows osv-scalibr (extractors feed an inventory, detectors read
it) and boughs' `internal/agent/<name>` split. jarx adds the `redact` and
`netguard` choke points that neither of those has.

## Data flow for one `jarx scan`

1. **platform** works out the OS paths. **discover** merges the agents'
   project records with the repos in `jarxdir`, then walks each repo with
   hardened `git ls-files` or the fallback walk.
2. Each **adapter** reads its files through `fsys`, parses them (JSON, JSONC,
   TOML, frontmatter), applies its own precedence and trust rules, and sends
   every string through **redact** before it reaches the model. Keys it
   doesn't recognize go to `model.Unknown`.
3. **probe** asks the model which servers the agent would start. Up to 4 run
   at once. **proc** spawns stdio servers in a job or process group.
   **netguard** handles remote servers. **mcp** sends `initialize` and the
   list calls. Results go through redact and land on `model.Server` with a
   status.
4. **history** loads its cursor and reads only new bytes. It records
   permission modes, cwds and secret fingerprints. Codex sqlite is opened
   read-only in place.
5. Each **analyzer** reads the model and emits findings:
   `finding.Finding{ID, Severity, Origin, Evidence redact.Text}`.
6. With `--llm`, **llm** shows the preview, sends redacted artifacts,
   validates the JSON (one retry) and checks the quotes. Results are cached by
   hash.
7. **snapshot** writes the masked JSON, prunes to 20 and diffs against the
   previous one. **drift** sends changed tools back through **poison**.
8. **report** prints the result. **ui** serves the same snapshot.

## Package layout

| Package | Job | PRD section |
|---|---|---|
| `cmd/jarx` | main, wiring only | CLI |
| `internal/cli` | subcommands with stdlib `flag` | CLI |
| `internal/platform` | OS facts only: home, GOOS, injected env, PATH, jarx's state dir, system roots (`/etc`, `/Library/Application Support`, `%ProgramData%`, `%ProgramFiles%`). Registry and plist reads land here in phase 3. Agent paths belong to the adapters, which join them onto these roots. | Scope, cross-platform rule |
| `internal/fsys` | the only file reader, with no write methods. Confined to the fake home under `--home`. A 10 MiB `ReadFile` cap, where every refused file is recorded so it becomes a "skipped, too large" finding and is never dropped silently. A skip list for bulk dirs (`node_modules`, `.git`, `vendor`, build output) that still keeps agent files inside them (`.claude/`, `.codex/`, `.agents/`, `CLAUDE.md`, `AGENTS.md`, `.mcp.json` and the like). Symlinks are listed but never descended into. | Walking a repo |
| `internal/jarxdir` | the only file writer: `os.Root` on jarx's state dir, atomic writes, for config, cursor, cache and fingerprint key | What jarx writes to disk |
| `internal/redact` | `Text` type, scrubber that always masks pattern matches (with a likely placeholder flag for low entropy), `Secret` for values known to be secret, masks like `REDACTED:<type>:<12 hex fingerprint>`, HMAC fingerprint with a per-install key created lazily in the state dir. The secret patterns themselves arrive with `catalog` in phase 3. | Promise 4, Secrets |
| `internal/model` | agent-neutral inventory, `Origin`, `Unknown` | Architecture |
| `internal/finding` | Finding, severity, rule registry with IDs | Detection rules |
| `internal/discover` | project records, hardened git walk, stale detection | Project discovery |
| `internal/agent` | adapter interface, shared parsers (jsonc, frontmatter, `@` imports) | Architecture |
| `internal/agent/claude` | Claude paths, precedence, trust, MCP approval, modes | Scope: Claude Code |
| `internal/agent/codex` | Codex paths, profiles, legacy `sandbox_mode` switch, requirements | Scope: Codex CLI |
| `internal/catalog` | embedded data: builtin tools, vendors, advisories, secret patterns, each with an "as of" stamp | Built-in tools catalog, Vendor badge, Advisory data |
| `internal/credmeta` | cred locations and safe metadata parsers (aws config, ssh header, gh hosts, `.env` keys) | Credentials |
| `internal/analyze/secrets` | prefix and entropy patterns, the sees state | Secrets |
| `internal/analyze/poison` | text rules over every text the agent reads | Detection rules |
| `internal/analyze/perms` | effective permissions with origin and in-effect reason | Effective permissions view |
| `internal/analyze/reach` | per-channel verdicts, observed modes, credential view | Reachability verdicts, Credential view |
| `internal/netguard` | the one HTTP client: dial-time IP block, no redirects, no proxy | Network calls |
| `internal/proc` | `proc_windows.go` job objects, `proc_unix.go` process groups, baseline env | How a stdio server is started |
| `internal/mcp` | list-only client: stdio, streamable HTTP, legacy SSE, paging | The MCP client |
| `internal/probe` | which servers, env expansion rules, concurrency, status | MCP probing, Server status |
| `internal/analyze/capability` | three-layer view per tool | Capability view |
| `internal/analyze/egress` | the "where your agent talks to" panel | Where your agent talks to |
| `internal/snapshot` | versioned schema, retention, diff | Snapshots and diff |
| `internal/analyze/drift` | hash diffs, rerun poison on changed tools | Snapshots, Drift |
| `internal/history` | cursor, jsonl, zstd and read-only sqlite readers (observed formats) | Session history |
| `internal/analyze/versions` | installs, PATH winner, advisory match, catalog age warning | Agent installs and versions |
| `internal/analyze/unknown` | the unknown settings report | Unknown settings report |
| `internal/report` | the only output writer: `Out` and `Err` streams that take a literal format and `redact.Text` values, and an `Error` that scrubs error text. Grows into the terminal report in phase 2. | CLI |
| `internal/ui` | server, middleware (host, token, CSRF, CSP), templates, embedded static files | Dashboard |
| `internal/keystore` | go-keyring for jarx's own entry, or an env var name | Optional LLM review |
| `internal/llm` | OpenAI-compatible client over netguard, preview, schema check and retry, quote check, cache | Optional LLM review |
| `internal/fakemcp` | a tiny MCP server (stdio and HTTP) with scripted tools, used by probe tests and the demo home | MCP probing, Demo home |
| `tools/vendorseed` | dev-only registry seeding where the namespace matches the vendor domain. Never linked into jarx. | Vendor badge |
| `testdata/<agent>/<version>/` | fake home trees per agent version | Fixtures per agent version |
| `testdata/demo/` | the demo home with planted problems | Demo home |
| `internal/analyze/<name>/testdata/<RULE-ID>/{poisoned,clean}/` | each rule's own fixtures | Testing and done criteria |

### Fixtures

- **Per rule:** every rule ID gets a `poisoned/` and a `clean/` dir, written
  first as the failing test (TDD). A table test walks all rule dirs, so a
  rule without both fixtures fails the build.
- **Per agent version:** fake home trees under `testdata/<agent>/<version>/`.
  When a format changes, a new version dir is added and the old ones keep
  passing.
- **History shapes:** Claude transcripts and Codex rollouts follow our
  format notes in the boughs repo (`docs/format-claude-code.md`,
  `docs/format-codex.md`), including replay: Claude replays inside one
  transcript, and Codex replays earlier items into a new rollout under
  `sessions/YYYY/MM/DD/`. Fields those notes don't cover (mode fields, `.zst`,
  sqlite) are built from observed structure, with a note in the fixture.
- **Demo home:** `testdata/demo/` is a full fake home with planted problems.
  Its risky MCP server is `internal/fakemcp`, so probing it runs our code,
  not a real package. A test runs `jarx scan --home testdata/demo` and checks
  for the expected findings, so the demo can't silently stop showing them.
- **Line endings:** `.gitattributes` sets `* text=auto eol=lf`, and marks
  `*.sqlite`, `*.zst` and images as `binary`, so fixture bytes (and hashes)
  are identical on Windows and Linux runners.

## Dependencies

Stdlib plus these, and depguard enforces the list:

- `github.com/BurntSushi/toml`
- `github.com/zalando/go-keyring`
- `github.com/klauspost/compress` (zstd)
- `modernc.org/sqlite`
- `golang.org/x/sys` (Windows job objects)

`go.mod` targets the latest stable Go (1.27.4 right now). jarx needs at least
1.25 for `http.CrossOriginProtection` and `os.Root`.

## CI

One workflow, `.github/workflows/ci.yml`. The repo is private, so it's set up
to keep Actions minutes low:

- **Every push, any branch:** the linux jobs (test, lint, vuln).
- **Pull requests:** only the windows and macos test jobs. The PR branch
  already got linux from its push, so linux doesn't run twice.
- Newer runs on the same branch cancel older ones. Every job has a timeout,
  the token is read-only, and checkout doesn't keep credentials.

Jobs:

- **test:** `go build ./...`, `go vet ./...` and `go test -race ./...` (with
  `CGO_ENABLED=1` for the race detector). Every step runs under bash on every
  runner, because PowerShell splits `-coverprofile=...` badly.
- **lint:** a gofmt check, then `go mod tidy -diff`, then golangci-lint
  v2.15.0. The config (`.golangci.yml`) uses `default: all`, and every
  disabled linter has a written reason. golangci's gosec linter covers gosec,
  so there's no separate job. `forbidigo` and `depguard` hold the choke points.
- **vuln:** govulncheck, run with `go run` at a pinned version.

The Go version comes from `go.mod`, so CI and local builds match. Every action
is pinned by SHA with the version in a comment.

Added in a later phase:

- **offline** (phase 2): on ubuntu, `unshare -n` runs
  `jarx scan --home testdata/demo` and expects success. With no network
  namespace, any network call fails the job, which proves the zero-network
  mode. `--no-probe` and `--no-history` get added to that command when they
  exist (phases 4 and 6).

Not set up for now, since the repo is private: CodeQL, Dependabot and any
release workflow. Bumping action SHAs is manual until then.

There's no Makefile, since make is awkward on Windows. CONTRIBUTING lists the
same commands CI runs. Fuzzing is for later.

## Build phases

jarx gets built in eight phases. Each phase only uses what came before it and
ends with something you can run or see. Choke points come first, so nothing
ever gets written against a looser version of them.

Each phase is one PR, opened as a draft early so CI runs on all three OSes
on every push. Each item in [progress.md](progress.md) is one commit in that
PR. That file is the checklist, and it gets ticked in the same commit as the
work.

`jarx scan` grows a little in every phase. Each phase adds to `testdata/demo/`
too, so the thing you run at the end of a phase shows that phase's work.

### Phase 1: Foundation

Repo skeleton, CI, lint guards, the CLI skeleton (`scan`, `--version`),
`platform`, `fsys` and `jarxdir`, and the first bits of `testdata/demo/`.

- The golangci config with `forbidigo` and `depguard` comes first. The rules
  have to exist before the code they guard, or the first package written
  breaks them and nobody notices.
- `.gitattributes` has to come before the first fixture, or Windows checkouts
  get CRLF bytes and hashes differ from Linux CI.
- Everything reads paths and files through `platform`, `fsys` and `jarxdir`,
  and tests inject fakes through `platform.Env`. If they came later, early code
  would call `os.UserHomeDir` directly and tests would touch the real machine.
- `--home` lands here, with `platform`, since that's where the fake home gets
  built.

**Run it:** `jarx scan --home testdata/demo` prints what jarx resolved: the
home dir, the OS, where the env comes from, the system roots (skipped with
`--home`) and jarx's own state dir, each with whether it exists. Without
`--home` it does the same for the real machine, existence only.

### Phase 2: Core engine

`redact`, `model` and `finding`, `netguard`, `discover`, `report`, the
project-record readers in both adapters, and `jarx setup repo add|rm`.

- `model` uses `redact.Text`, so `redact` comes first. The no-leak test suite
  starts here and grows with each phase.
- `model` and `finding` are the shape every adapter writes into and every
  analyzer reads from. Getting `Origin` right now saves rewriting every
  adapter later.
- `netguard` has no users yet, but it's a choke point. Building it before
  `mcp` and `llm` means neither ever has a moment where it makes its own
  client. Its tests (redirects, link-local, metadata, IPv6 forms that wrap
  IPv4) don't depend on anything else.
- `discover` needs project records, and only adapters know where those live
  (`~/.claude.json`, Codex `[projects]`), so the record readers land here as
  the first piece of each adapter.
- The offline CI job turns on.

**Run it:** `jarx scan --home testdata/demo` lists every project both agents
know about, marks stale ones, and shows file counts from the hardened git
walk. `jarx setup repo add <path>` adds a project and the next scan lists it.

### Phase 3: Instruction files and settings

The Claude adapter, then the Codex adapter: settings with precedence and
trust, instruction files (parent folders, subfolders, `@` imports), memory,
output styles, skills, commands and hooks. Then `catalog` (secret patterns),
`analyze/secrets`, `analyze/poison`, `analyze/perms`, `analyze/unknown`, and
`snapshot` with diff.

- Claude goes first because it has the most surface and the most precedence
  rules. Codex right after is what proves the model really is agent-neutral,
  while Claude-shaped assumptions are still cheap to fix.
- `perms` lands here because it's built from settings, and both the MCP
  capability view (phase 4) and the credential verdicts (phase 5) need it.
- `snapshot` lands here so every later phase can see regressions between
  scans, and because drift (phase 4) needs it.

**Run it:** `jarx scan --home testdata/demo` shows each project's instruction
files, skills, hooks and effective permissions, and flags the demo's planted
problems: hidden unicode, the HTML comment aimed at the agent, the skill with
injection text, `bypassPermissions` and `Bash(*)`. Change a demo file, scan
again, and the change shows up.

### Phase 4: MCP

MCP config in both adapters with the "would the agent start it" logic, then
`fakemcp`, `proc`, `mcp`, `probe`, the MCP config rules, `analyze/capability`
and `analyze/drift`.

- This is the riskiest part (it runs code and talks to the network), so it
  comes after every guard it relies on: redact for stderr, netguard for remote
  servers, the model for "would the agent start it".
- `fakemcp` comes first so every probe test has a server to talk to. The
  `go/ast` method test lands with `mcp`.
- `--no-probe` lands here.

**Run it:** `jarx scan --home testdata/demo` probes the demo's fake poisoned
server, lists its tools with a status, and flags the poisoned descriptions,
the unpinned `npx` server and the token in the URL. `--no-probe` shows the
servers as "not started".

### Phase 5: Credentials and reach

`credmeta`, the built-in tools catalog, `analyze/reach` with the credential
view, `analyze/egress` and `analyze/versions`.

- `reach` needs effective permissions (phase 3), the built-in tools catalog,
  and MCP servers as a channel (phase 4). It ships with configured verdicts.
  Observed modes come in phase 6.
- `egress` needs MCP host status, so it comes after probing.
- `versions` is the "vulnerable agent version" exposure check, so it sits with
  the other exposure work.

**Run it:** `jarx scan --home testdata/demo` shows each credential location
per project with its state (can read, can use, not reachable), per-channel
verdicts and the why trail. It also shows where each agent talks to and flags
a vulnerable agent install in the demo.

### Phase 6: History

The history cursor and readers for Claude transcripts, Codex rollouts (zstd)
and Codex sqlite, then wiring the results into what already exists.

- It comes last among the core features because it reads undocumented
  formats. It feeds observed modes into reach, the "sees" state into the
  credential view, and session cwds into discover. Those already exist and
  just get more data.
- `--no-history` lands here.

**Run it:** the demo home gets fake transcripts and rollouts. `jarx scan
--home testdata/demo` shows things like "14 of 20 sessions in bypass" next to
a verdict, and a leaked secret masked with its file and line.

### Phase 7: Dashboard

Before this phase starts, we stop and talk about how the UI should look.

`ui` with its security middleware first (host check, token cookie, CSRF, CSP)
and its tests before any page. Then the pages, the snapshot picker, and the
write actions (repo add and remove, rescan).

- The dashboard shows a snapshot, so it waits until the snapshot has
  everything in it.

**Run it:** `jarx ui --home testdata/demo` and click through it.

### Phase 8: LLM review

`keystore`, `jarx setup llm`, the `llm` client (preview, schema check and
retry, quote check, cache), the canary test, `jarx scan --llm` and the
dashboard button.

- It's optional, off by default, and the only feature that sends content off
  the machine. It goes last, so it sits on top of a finished redact, netguard
  and canary test suite.

**Run it:** `jarx setup llm`, then `jarx scan --llm --home testdata/demo`
against your own endpoint.
