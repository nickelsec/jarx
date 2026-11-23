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
    (phase 5), and the line a secret is on (f70cc46)
- [x] `analyze/poison`: hidden text and poisoned content rules. 13 rules
  over instructions, memory, skills, hook commands and hook scripts: tag
  characters, bidi controls, zero-width characters, terminal escapes, HTML
  comments the agent reads (block comments in CLAUDE.md skipped, since
  Claude strips them), text aimed at the agent, the same found in hidden
  text, exfil shapes, credential file pointers, and the PRD's four hook
  rules. Fixtures per rule, the demo's hidden comment, and `-text` for
  analyzer fixtures in `.gitattributes`
  - Not covered yet: MCP text (phase 4), lying annotations and tool
    shadowing (phase 4), Codex memories, look-alike characters, phrases in
    languages other than English, and comments that only show when the
    agent opens a CLAUDE.md with its Read tool (dfa8ee5)
- [x] `analyze/perms`: effective permissions view. Claude's sandbox and
  `enableAllProjectMcpServers` in the view, allows a deny or ask rule
  overrides marked not in effect, `PermissionRule.Target`, credmeta's sample
  credential paths, the embedded command table, and ten findings: bypass
  mode, no Codex sandbox, never asking, every command, grants that cover
  credential files, all project MCP servers, a retired approval policy, and
  allows that run any code, the repo's code, or a tool with an escape
  - Not covered yet: Codex per-tool `approval_mode` (phase 4), Codex
    execution-policy rules files, how two different Bash patterns overlap,
    `blockReadsOutsideWorkingDirectories` and the other `permissions.*`
    switches, sandbox network settings (phase 5 egress), and programs not in
    the command table (ef4961a)
- [x] `analyze/unknown`: unknown settings report. A Codex key table from
  the config reference (both files, with aliases), Claude's `$schema` and
  marketplace aliases, "did you mean" for likely typos, and three findings:
  an unknown key (info), a likely typo (medium), and a likely typo of a
  safety key (high). Also a finding for a Claude alias ignored next to its
  canonical key
  - Not covered yet: keys inside Codex `[hooks]` (the Hooks guide, not the
    reference, lists them), hooks.json and plugin manifests, MCP config keys
    (phase 4), and Claude's deprecated keys beyond `ignorePatterns`, since
    the index still lists the rest (b49a8f4)
- [x] `snapshot`: masked snapshots, retention, diff in `scan` output.
  Items with an identity and a state, texts kept as hashes, the newest 20
  kept, a note rather than an error for a broken or newer snapshot, and a
  `changes` section in `scan`. Also scrubbing made idempotent, with a guard
  against text dressed up as a mask, and the offline CI job allowing one
  snapshot
  - Not covered yet: servers, tools, prompts and resources (phase 4),
    verdicts (phase 5), the snapshot picker (phase 7), and named baselines
    (38873d0)
- [x] `report`: redesign the terminal output so a scan is easy to read,
  instead of every section printed in full. A header, the agents, what was
  scanned, one summary line, then findings grouped by project, worst first,
  with user-level problems once on their own. Short paths, at most 10
  findings per project but every high one, `--all` for everything, width
  and color and charset from `platform.DetectTerm`, and lines cut instead of
  wrapped. Also rule titles cut to 42 chars with the rest in `Detail`, and
  the banner with the version on every run
  - Not covered yet: MCP servers and agent versions in the agents block
    (phase 4 and the versions work), and the last line pointing to the
    dashboard instead of `--all` (phase 7) (0bf72ba)

**Run it:** `jarx scan --home testdata/demo` shows instruction files, skills,
hooks, permissions and the planted findings. Change a demo file and the diff
shows it.

## Phase 4: MCP

- [x] MCP config in the Claude adapter, with the "would it start" logic.
  User and local servers from `~/.claude.json`, `.mcp.json`, plugin servers,
  `managed-mcp.json` and `managedMcpServers`, each as a `model.Server` with
  a start state (starts, may start, not started, approval unknown). The
  policy follows the managed-mcp page: exclusive control, the denylist from
  every admin source, the allowlist with the managed-only lock, and
  `serverName`, `serverCommand` and `serverUrl` matching. Also `.mcp.json`
  approval with trust, the `/mcp` toggles, same-name precedence with "may
  start" when the winner won't start, plugin servers matched by endpoint,
  reserved names, servers in snapshots, a row in the scanned block and the
  loads line, the full list in `--all`, the demo's `.mcp.json`, and the demo
  test's copy starting without the local jarx state. A follow-up puts every
  server's command, args, URL, env and header values through the secrets
  scan, since most real tokens sit in the user and local servers in
  `~/.claude.json`, and masks an env or header value by its name
  (`API_TOKEN=...`) even when it has no known format
  - Not covered yet: inline `mcpServers` in subagent frontmatter (no YAML
    parser), servers on the agents row (they come with probe status),
    `${VAR}` expansion when matching list entries (a reference there makes
    the server "may start"), unknown keys inside server entries, claude.ai
    connectors with `disableClaudeAiConnectors` and `allowAllClaudeAiMcps`,
    Claude in Chrome next to `managed-mcp.json`, and two plugins defining
    the same endpoint (c3f9aef, 1fb8423)
- [x] MCP config in the Codex adapter, with the "would it start" logic.
  `[mcp_servers.<id>]` from every config layer, with the layer's trust and
  profile rules, `enabled`, the stdio and streamable HTTP shapes, and the
  `requirements.toml` allowlist (id and identity, string and matcher forms,
  exact, prefix and whole-value regex, empty list turns everything off).
  Also every Codex field in the model (env_vars, cwd, bearer and header env
  vars, auth, enabled and disabled tools, approval modes), the same id in
  two layers with a note on fields that may merge in, `agent.Pair` shared by
  both adapters for masking by name, the new fields in the snapshot hash,
  and the demo's user server that a trusted repo redefines
  - Not covered yet: Codex plugin servers (`plugins.<plugin>.mcp_servers`,
    with Codex plugins), `environment_id` and remote executors,
    `startup_readiness` and `required`, and unknown values for
    `approval_mode` (the open item in the PRD) (ed1ccde)
- [x] `fakemcp`: scripted stdio and HTTP server. It speaks both protocol
  eras (2026-07-28 with `server/discover` and the version in `_meta`, and
  legacy `initialize`), streamable HTTP with the version header check, and
  the 2024-11-05 HTTP+SSE transport. Tools, prompts and resources go out
  byte for byte, and it records every message, so `Forbidden()` proves a
  client only listed. A script can make it hostile: hang on a method, delay,
  page forever, write garbage or huge replies, answer with the wrong id
  first, flood notifications, send the client sampling, roots and
  elicitation requests, answer lists with an `InputRequiredResult`, print a
  secret and escapes on stderr, exit early, and over HTTP answer a set
  status, redirect to the metadata address, or want a bearer token. The doc
  check for it found 2026-07-28 dropped `initialize`, so design.md and the
  PRD now say the client sends `server/discover` first and falls back to
  `initialize` for legacy servers
  - Not covered yet: the demo's poisoned server (it needs a way to start
    `fakemcp` under `--home`, which comes with probe), spawning child
    processes that outlive a kill (that test belongs to `proc`),
    `subscriptions/listen`, and the `-race` run here (no C compiler on this
    machine, so CI's linux job covers it) (f50540c)
- [x] `proc`: job objects on Windows, process groups on unix, baseline env.
  golang/go#79927 isn't fixed in Go 1.27.4: the proposal is still open,
  and the change landed on tip and was reverted on 2026-11-20. So it's the
  suspended start, with the main thread resumed through a Toolhelp32
  snapshot and `ResumeThread` (documented calls, unlike `NtResumeProcess`).
  Also the baseline env plus declared vars (never jarx's own env, and
  empty stays empty), stderr kept up to 64 KiB, `Find` on the env's PATH
  through fsys with PATHEXT on Windows and never under `--home`, a refusal
  to pass `cmd.exe` metacharacters to a `.bat` or `.cmd` file, and `proc`
  added to the lint rule that lets a package run processes. Tests rerun the
  test binary as a server that starts a grandchild, and check `Kill` takes
  both
  - Not covered yet: a server that leaves its process group with `setsid`
    on unix (in Limits), the Linux `Pdeathsig` backstop if jarx itself
    dies mid-probe, and the exec-bit and process-group tests, which run
    only on the linux and mac CI jobs since this machine is Windows
    (304399a)
- [x] `mcp`: list-only client, stdio, streamable HTTP, legacy SSE, paging,
  `go/ast` method test. `server/discover` first and `initialize` when the
  server is legacy (on stdio also when discover gets no answer), the HTTP
  fallbacks from modern to legacy streamable HTTP to HTTP+SSE on a 4xx
  without a JSON-RPC body, and refusals for a server with no version in
  common and an SSE endpoint on another origin. Paging stops at 50 pages,
  a repeated cursor or 32 MiB kept, and an `InputRequiredResult` gives no
  items. Server requests, notifications, wrong ids and garbage are skipped
  and counted, never answered. The request builder refuses any other
  method, and a `go/ast` test fails on any other method string in the
  package. Also `fakemcp` grew a strict modern era (no version in `_meta`
  is an error) and a `Capabilities` list, so the client's `_meta` and
  capability checks have something to fail against
  - Not covered yet: the legacy `Mcp-Session-Id` and the legacy version
    header aren't checked by `fakemcp`, the 32 MiB cap has no test, and
    `ttlMs` caching and `subscriptions/listen` aren't used (jarx lists
    once) (c7475f2)
- [x] `probe`: which servers, env expansion, concurrency, status,
  `--no-probe`. Every server that starts gets probed once per definition,
  4 at a time with 15s each, and ends with one of the PRD's statuses. Claude's
  `${VAR}` and `${VAR:-default}` with the path variables, its credential
  variables read as empty toward remote servers (the documented examples and
  their families), and Codex's `env_vars`, `bearer_token_env_var` and
  `env_http_headers`. A reference to an unset variable is "missing
  credential" and starts nothing. OAuth and headers helpers are "requires
  auth" without contact, a 401 or 403 is "requires auth" or "credential
  rejected" by whether creds were sent, and netguard's refusals are
  "blocked" or "insecure transport". Also `model.Launch` for the raw launch
  data (never printed or encoded, and a lint rule that lets only probe and
  tests unwrap it), masked offers, instructions and stderr on
  the server, the status and offers under `--all`, the server count on each
  agent's row, offers as snapshot items for drift, `ListSSE` for SSE
  servers, and `platform.LookupReal`. Under `--home` the only thing probe
  starts is the demo's fake server, jarx itself in a hidden mode, with a
  test that it never happens on the real machine; the demo gains its
  poisoned `notes-helper` server
  - Not covered yet: the probe's own findings on what servers offer (item 7
    and 8), the PRD's "allowed by the token" layer (it stays unknown), Codex
    plugin servers, and `${CLAUDE_PLUGIN_DATA}`, whose dir the docs don't
    name (a350c95)
- [x] MCP supply chain and config rules. Includes the rules item 1, 2 and 4
  set up: a repo server that takes your server's name, one name in two
  scopes with different endpoints, a repo redefining a Codex server whose
  lower layer sends a token, and `cmd.exe` metacharacters in the args of a
  `.bat` or `.cmd` server. Twelve rules on one definition in a new
  `analyze/mcpconfig` (`JARX-MCP-001` to `012`, with 71 poisoned and clean
  fixtures), and four in the adapters, which know the precedence:
  `JARX-CLAUDE-006` and `007`, `JARX-CODEX-009` and `010`. Rules run on
  servers that start, may start or wait on approval. The demo now flags its
  unpinned `npx` server, its repo script and the repo that redefines your
  Codex `search` server
  - Not covered yet: a local server can't be taken over (Claude ranks local
    above project), so CLAUDE-006 is user servers only; tokens in URLs and
    secrets in headers stay with `JARX-SECRET-002`; "forwarding the whole
    env" has no documented config key to check; and poison rules on what
    servers offer, lying annotations and tool shadowing come with item 8
    (6206ef4)
- [x] `analyze/capability` and `analyze/drift`. Each listed tool gets its
  layer 3 access (hidden, denied, asks, may run without asking, runs
  without asking) with the rule or mode behind it, shown under `--all`:
  Claude's `mcp__` rule forms with name normalizing, plugin servers, the
  `__` name quirk and the default modes, and Codex `enabled_tools`,
  `disabled_tools`, approval modes, the destructive annotation rule and
  `approval_policy`. Two rules on it, `JARX-CAP-001` and `002`, and two on
  drift against the last snapshot, `JARX-DRIFT-001` and `002`. Also the
  poison rules on what servers offer (instructions and every string in a
  tool, prompt or resource entry, one finding per rule per tool),
  `JARX-POISON-014` for lying annotations and `015` for tool shadowing, one
  change-word list in `model.Offer.ChangeWord`, and CAP-001 as one finding
  per allow rule or mode, listing its tools. The demo's MCP servers moved
  to their own `projects/tools`, which allows the poisoned server's tools,
  so the default view (not just `--all`) shows the poisoned descriptions,
  the unpinned `npx` server and the URL token, with a test that checks it.
  A changed demo tool raises DRIFT-001
  - Not covered yet: layer 2, what the server's token allows (it stays
    unknown); Codex `auto` and `approve`, whose meaning the docs don't
    give; allow rules on a tool's input, which Claude doesn't match for MCP;
    shadowing across agents or with built-in tools; and drift on servers
    whose file or name changed, which counts as a new server (2867b2e)

**Run it:** `jarx scan --home testdata/demo` probes the fake poisoned server
and flags it.

## Phase 5: Credentials and reach

- [x] `credmeta`: cred locations and safe metadata parsers. One table of
  places from each CLI's docs on Windows, macOS and Linux, with the env vars
  that move them (`AWS_SHARED_CREDENTIALS_FILE`, `GH_CONFIG_DIR`,
  `CLOUDSDK_CONFIG`, `GOOGLE_APPLICATION_CREDENTIALS`, `KUBECONFIG`,
  `NETRC` and the rest). The phase 3 table had gh and gcloud wrong on
  Windows and knew no env vars, so a moved credential got past the read
  guard; the guard now checks every place and still the old defaults.
  Parsers keep only the allowed fields for aws, gh, docker, kube, ssh (OpenSSH,
  PEM, PKCS#8 and PuTTY keys), git, netrc, npm, pypi and `.env`, with line
  readers for the two YAML shapes and no new dependency. gcloud, azure,
  gnupg, aws's token caches and the agents' login files are existence only,
  and a dir like gcloud's is one entry with its file count.
  `fsys.CredentialFacts` is the one way past the guard, returns facts and
  never bytes, and only `discover` may call it (lint). Also
  `model.Credential` on the scan and on each project (`.env`, keys, a
  project `.npmrc`), credentials in snapshots as hashes, a row in the
  scanned block and the full list under `--all`, canaries in every secret
  slot of the fixtures, ssh test keys built in code so nothing in the repo
  reads as a private key, and fake credentials in the demo home
  - Not covered yet: ssh keys `~/.ssh/config` points at elsewhere,
    GnuPG's Windows default dir (both in Limits), the files inside gcloud's
    config dir (not documented), `--kubeconfig` and other per-run flags,
    aws `credential_process` and kube `exec` commands (named, never run),
    and the per-project reach line (item 5)
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
