# jarx progress

The checklist for the build phases in [design.md](design.md#build-phases).
Each item is one PR. Tick it in the same PR as the work, and add the PR number.

## Phase 1: Foundation

- [x] skeleton and CI: `go.mod`, `.gitattributes`, `cmd/jarx`, workflow,
  golangci config with forbidigo and depguard (#2)
- [x] build phases, progress checklist, CLI trimmed to scan, ui and setup
- [ ] CLI skeleton: move to `internal/cli`, `--version` instead of the
  `version` subcommand, `scan` command
- [ ] `platform`: injected `Env`, OS paths, managed dirs, `--home`
- [ ] `fsys` (read-only view, size caps, skip list) and `jarxdir` (`os.Root`
  on the jarx config dir)
- [ ] `scan` prints what jarx resolved, first bits of `testdata/demo/`

**Run it:** `jarx scan --home testdata/demo` prints the resolved paths and
whether each exists.

## Phase 2: Core engine

- [ ] `redact`: `Text` type, scrubber, `REDACTED:<type>`, fingerprint, start
  of the no-leak suite
- [ ] `model` and `finding`: inventory, `Origin`, `Unknown`, rule registry
- [ ] `netguard`: the one HTTP client, dial-time IP block, no redirects, no
  proxy
- [ ] `discover` and `report`: project records from both adapters, hardened
  git walk, stale detection, terminal output
- [ ] `jarx setup` and `setup repo add|rm`
- [ ] offline CI job

**Run it:** `jarx scan --home testdata/demo` lists every known project with
stale ones marked.

## Phase 3: Instruction files and settings

- [ ] Claude adapter: settings, precedence, trust
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
