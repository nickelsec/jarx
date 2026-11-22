# jarx progress

The checklist for the build phases in [design.md](design.md#build-phases).
Each phase is one PR, and each item is one commit in it. Tick the item in the
same commit as the work. The next commit adds that commit's short hash.

## Phase 1: Foundation

- [x] skeleton and CI: `go.mod`, `.gitattributes`, `cmd/jarx`, workflow,
  golangci config with forbidigo and depguard (84504b1)
- [x] build phases, progress checklist, CLI trimmed to scan, ui and setup
  (bdc8f63)
- [x] CLI skeleton: move to `internal/cli`, `--version` instead of the
  `version` subcommand, `scan` command (a0613b1)
- [x] `platform`: injected `Env`, OS facts and system roots, `--home`, `scan`
  prints what platform resolved, `.jarx-state` ignored under testdata (200c17d)
- [x] `fsys` (read-only view, size caps, skip list) and `jarxdir` (`os.Root`
  on the jarx config dir), with lint rules that make them the only reader and
  writer (865ab36)
- [x] `scan` adds jarx's state dir and exists checks, first bits of
  `testdata/demo/` (b27607b)

**Run it:** `jarx scan --home testdata/demo` prints the resolved paths and
whether each exists.

## Phase 2: Core engine

- [x] `redact`: `Text` type, scrubber, `REDACTED:<type>`, fingerprint, start
  of the no-leak suite. Also a minimal `report` as the only output writer,
  with lint rules banning output everywhere else, and `cli` moved onto it
  (d0ca3da)
- [x] `model` and `finding`: inventory, `Origin`, `Unknown`, rule registry.
  Turn `fsys` skips into "skipped, too large" info findings. Also `Setting[T]`
  for values set in more than one scope, and the no-raw-string model test
  (f2508f2)
- [x] `netguard`: the one HTTP client, dial-time IP block, no redirects, no
  proxy. Also loopback-only plain http checked per connection, response size
  and time caps, and lint bans on TLS, DNS, smtp and rpc outside netguard
- [ ] `discover` and `report`: project records from both adapters, hardened
  git walk, stale detection, the project listing in `report`
- [ ] `jarx setup` and `setup repo add|rm`
- [ ] offline CI job

**Run it:** `jarx scan --home testdata/demo` lists every known project with
stale ones marked.

## Phase 3: Instruction files and settings

- [ ] Claude adapter: settings, precedence, trust. Includes the Windows
  registry and macOS plist reads in `platform` (first use of `golang.org/x/sys`)
  and checking the managed paths against the official docs
- [ ] Claude adapter: instruction files, `@` imports, memory, output styles
- [ ] Claude adapter: skills, commands, subagents, plugins, hooks
- [ ] Codex adapter: config, profiles, precedence, trust, requirements
- [ ] Codex adapter: instruction files, skills, hooks
- [ ] `catalog` secret patterns and `analyze/secrets`
- [ ] `analyze/poison`: hidden text and poisoned content rules
- [ ] `analyze/perms`: effective permissions view
- [ ] `analyze/unknown`: unknown settings report
- [ ] `snapshot`: masked snapshots, retention, diff in `scan` output

**Run it:** `jarx scan --home testdata/demo` shows instruction files, skills,
hooks, permissions and the planted findings. Change a demo file and the diff
shows it.

## Phase 4: MCP

- [ ] MCP config in the Claude adapter, with the "would it start" logic
- [ ] MCP config in the Codex adapter, with the "would it start" logic
- [ ] `fakemcp`: scripted stdio and HTTP server
- [ ] `proc`: job objects on Windows, process groups on unix, baseline env.
  First check whether Go 1.27 fixed golang/go#79927 (design.md says the fix
  "isn't in Go 1.25"). If it did, use the `SysProcAttr` fix instead of the
  suspended start and update design.md.
- [ ] `mcp`: list-only client, stdio, streamable HTTP, legacy SSE, paging,
  `go/ast` method test
- [ ] `probe`: which servers, env expansion, concurrency, status,
  `--no-probe`
- [ ] MCP supply chain and config rules
- [ ] `analyze/capability` and `analyze/drift`

**Run it:** `jarx scan --home testdata/demo` probes the fake poisoned server
and flags it.

## Phase 5: Credentials and reach

- [ ] `credmeta`: cred locations and safe metadata parsers
- [ ] built-in tools catalog
- [ ] `analyze/reach`: Claude channels and verdicts
- [ ] `analyze/reach`: Codex channels and the legacy `sandbox_mode` switch
- [ ] credential view
- [ ] `analyze/egress`: where your agent talks to
- [ ] `analyze/versions`: installs, PATH winner, advisories

**Run it:** `jarx scan --home testdata/demo` shows credential states,
per-channel verdicts and the egress panel.

## Phase 6: History

- [ ] history cursor and Claude transcripts
- [ ] Codex rollouts (zstd) and sqlite
- [ ] observed modes into reach, "sees" state, session cwds into discover,
  `--no-history`

**Run it:** `jarx scan --home testdata/demo` shows session mode counts and a
masked leak.

## Phase 7: Dashboard

- [ ] talk through how the UI should look (before any `ui` code)
- [ ] `ui` server and security middleware with tests
- [ ] pages
- [ ] snapshot picker and write actions (repo add and remove, rescan)

**Run it:** `jarx ui --home testdata/demo`.

## Phase 8: LLM review

- [ ] `keystore` and `jarx setup llm`
- [ ] `llm` client: preview, schema check and retry, quote check, cache,
  canary test
- [ ] `jarx scan --llm` and the dashboard button

**Run it:** `jarx setup llm`, then `jarx scan --llm --home testdata/demo`.
