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
  (f86f249)
- [x] `discover` and `report` (a): project records from both adapters, stale
  and outside-home statuses, the project and findings listing in `report`,
  `scan [path...]`, and demo records in `testdata/demo/` (723897b)
- [x] `discover` (b): the hardened git walk and the fallback walk, file
  counts, and the `exec:` lint rule (86e06a5)
- [x] `jarx setup` and `setup repo add|rm`, with `--home`, and saved repos
  in every scan (451ba14)
- [x] offline CI job, with a control step that proves the namespace has no
  network (1b48b2f)

**Run it:** `jarx scan --home testdata/demo` lists every known project with
stale ones marked.

## Phase 3: Instruction files and settings

- [x] Claude adapter: settings, precedence, trust. Includes the Windows
  registry reads in `platform` (first use of `golang.org/x/sys`), the settings
  index scope table, and checking the managed paths against the official docs
  (8257aaa)
  - Not covered yet: the local settings file at the repo root when Claude
    starts in a subfolder, local files tracked in git (they wait for trust),
    "can't be set from this file" for keys outside `permissions`, and the
    keys Claude reads from every admin source (they come with the items
    that read those keys)
- [x] Claude adapter: instruction files, `@` imports, memory, output styles.
  Also the read guards an `@` import made necessary: `fsys` refuses
  credential files (even behind a symlink), network paths and non-regular
  files, `credmeta.Location` starts early for that, and `report` escapes
  control and bidi characters (1c1c423)
  - Not covered yet: `claudeMdExcludes`, symlinked rules that point outside
    the project (Claude treats them like external imports), output styles in
    `.claude/output-styles/` between the working dir and the repo root,
    plugin output styles (with plugins), whether external imports were
    approved (not documented), and how Claude treats an import path that
    ends in punctuation like `@docs/setup.md.` (not documented; jarx keeps
    the documented rule, the path runs to the first space)
- [x] Claude adapter: skills, commands, subagents, plugins, hooks. Also the
  canary test that proves nothing they declare runs, and two findings:
  skills that run shell commands before Claude sees them, and repository
  skills that grant tools or add hooks without the trust check
  - Not covered yet: frontmatter hooks are kept as raw text (no YAML
    parser), `@skills-dir`, `@inline` and synced plugins, synced skills,
    plugin MCP and LSP servers and monitors (MCP comes in phase 4), plugin
    output styles, `extraKnownMarketplaces`, `allowedHttpHookUrls`,
    `strictPluginOnlyCustomization`, project subagent hooks waiting for
    trust, skill `paths` and supporting files, skills in parent dirs up to
    the repo root, and command subfolders (7e18571)
- [x] Codex adapter: config, profiles, precedence, trust, requirements. Also
  the generic `Options` and read and write rules in the model, and five
  findings for settings that quietly override others: a repository's
  `sandbox_mode` turning off your permission profile (high), your own
  `sandbox_mode` doing the same (medium), a repository changing your
  permission profile (medium), and a legacy `managed_config.toml` and legacy
  profiles (info)
  - Not covered yet: Codex unknown keys (no key table yet), the project
    ignored keys once options need them (phase 5 egress), managed
    `deny_read` and the `[[remote_sandbox_config]]` host overrides,
    `managed_config.toml` fields that turn into requirements, granular
    approval policies beyond their name, `extends` chains, and the
    `untrusted` approval policy's fallback (ac09450)
- [x] Codex adapter: instruction files, skills, hooks. Also the
  `project_doc_max_bytes` handling for its two documented readings, a note
  and a byte limit on instructions and a note on hooks in the model, Codex
  hooks in the no-execution canary, and a finding for a repository changing
  which instructions Codex loads
  - Not covered yet: Codex plugins and their hooks and skills, Codex
    memories, skill metadata beyond the name (`agents/openai.yaml`),
    `[skills.bundled]`, worktrees reading hooks from the main checkout,
    `--dangerously-bypass-hook-trust`, and `command_windows` in managed hooks
    (1b700af)
- [x] `catalog` secret patterns and `analyze/secrets`. About 20 token
  formats from provider docs and RFCs, a name rule for values with no
  documented format, placeholders judged by shape for named values, `redact`
  masking one group of a match, a scrubbed copy of every settings and config
  file in the model, and three findings: a secret the agent sees (high), a
  secret in a config file or hook (medium), and a likely placeholder (info)
  - Not covered yet: the PRD's 30 to 50 formats (npm, OpenAI and Hugging
    Face don't document a prefix, so only the name rule finds them), MCP
    configs (phase 4), Codex config files that aren't valid TOML, plugin
    `installed_plugins.json`, the "sees" state in the credential view
    (phase 5), and the line a secret is on
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

- [ ] history cursor and Claude transcripts, including the real `cwd` behind
  each `~/.claude/projects/` folder
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
