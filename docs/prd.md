# jarx PRD

Status: draft v1. Last updated 2026-11-22.

## What jarx is

jarx is a local tool that shows what Claude Code and Codex can see and reach on
a dev machine: instruction files, MCP servers and their tools, skills, hooks,
permissions and credentials. It also flags anything that looks poisoned or
leaky.

It ships as one Go binary with a CLI and a local dashboard. It needs no
account and talks to no vendor cloud.

## The problem

People run coding agents with a pile of config they never look at as a whole.
User settings, project settings, `.mcp.json` files pulled in with a clone,
plugins, skills, hooks and old session logs all stack up. Nobody can answer
simple questions like "can the agent read my AWS creds in this repo without
asking me?" or "did this MCP server's tool descriptions change since last
week?"

Existing scanners either upload your setup to their cloud or run regex over
one folder. jarx stays on the machine and does three things they don't:

1. Finds every project the agents know about, using the agents' own records.
2. Actually lists each MCP server's tools, prompts and resources by starting
   the servers the agent would start anyway.
3. Works out which credentials the agent can really read, per channel, from
   the permission and sandbox settings and from the modes you actually ran in.

## Users

- **Primary: the individual dev** auditing their own laptop. This person
  breaks every tie.
- **Secondary: security folks** who want to know what agents expose. v1 helps
  them on a single machine. Their bigger needs (export, CI gate, fleet view)
  are listed under non-goals.

## Goals for v1

- Show the full agent surface for Claude Code and Codex CLI on Windows, macOS
  and Linux.
- List real MCP tools, prompts and resources, safely.
- Give a per-channel, per-project verdict for every known credential location.
- Flag poisoned or risky artifacts with built-in rules, plus an optional LLM
  review the user turns on.
- Snapshot every scan and show what changed since the last one.

## Non-goals for v1

- CI gate: no exit codes by severity, no JSON or SARIF export.
- Fleet or multi-machine views.
- Agents other than Claude Code CLI and Codex CLI (no Claude Desktop, Cursor,
  Gemini CLI, IDE-specific config).
- Typosquat or lookalike detection for MCP packages.
- Behavior evidence from history beyond permission modes (for example "a tool
  read ~/.ssh on Tuesday").
- Cross-artifact LLM reasoning.
- User-written rule files.
- Release binaries. `go install` is enough for now.
- Any change to agent config. jarx never edits it.

## Hard promises

These go in the README and each one gets tests.

1. **No telemetry and no update check.** jarx never phones home.
2. **No account, no vendor cloud.** The only outside service jarx can talk to
   is an LLM endpoint the user set up and chose to call.
3. **Never stores, shows or sends credential values.** jarx does see secrets
   in memory while it masks them (inline in config, instruction files,
   history), but a value never leaves that step. `.env` files are opened for
   key names only. Ambient CLI creds (aws, gh, gcloud, ssh and similar) get
   existence plus safe metadata. The agents' own login files get existence
   only. jarx never reads other apps' keychain entries.
4. **Every secret jarx finds is masked** the moment it's found, wherever it
   was found (config, instruction, memory, skill and hook files, history,
   probe stderr). It shows up only as `REDACTED:<type>` plus a fingerprint,
   and never reaches the terminal, dashboard, snapshots, logs or the LLM.
5. **Never calls an MCP tool or reads an MCP resource.** It only sends
   `initialize` and the list methods.
6. **Never writes agent config.**
7. **Dashboard binds to 127.0.0.1 only**, with a token, Host check and Origin
   check.
8. Every network call jarx makes is listed in [Network calls](#network-calls).

## Scope: what jarx collects

All paths below come from the official docs (see [Sources](#sources)). `~` is
`%USERPROFILE%` on Windows.

### Claude Code

- **Settings:** managed (`managed-settings.json` and `managed-settings.d/*.json`
  in the managed dir; macOS `/Library/Application Support/ClaudeCode/`,
  Linux/WSL `/etc/claude-code/`, Windows `C:\Program Files\ClaudeCode\`; plus
  the `Settings` value under the Windows `HKLM` and `HKCU`
  `SOFTWARE\Policies\ClaudeCode` keys), user `~/.claude/settings.json`,
  project `.claude/settings.json`, local `.claude/settings.local.json`, and
  `~/.claude.json`. Honor `CLAUDE_CONFIG_DIR`. The macOS managed preferences
  domain isn't read (see [Limits](#limits)).
- **Precedence:** managed > `--settings` > local > project > user. Inside
  managed, sources rank remote > MDM > files > HKCU, and by default the first
  one with a policy key wins (`managedSourcesBehavior`). Each key's allowed
  files come from the settings index, so a managed-only key in a project file
  is listed as not in effect. Two quirks that matter: `defaultMode` of `auto`
  or `bypassPermissions` is ignored from project and local files, and project
  `allow` rules, `additionalDirectories`, `extraKnownMarketplaces` and most
  `env` values only count once the folder is trusted. Deny and ask apply right
  away. Trust is `projects["<path>"].hasTrustDialogAccepted` in
  `~/.claude.json`, keyed on the git repo root. A missing or odd value is
  "unknown".
- **MCP:** local and user scope in `~/.claude.json`, project `.mcp.json`,
  plugin `.mcp.json` or `plugin.json`, managed `managed-mcp.json`, and the
  `mcpServers` frontmatter in agent and subagent files (`.claude/agents/`,
  `~/.claude/agents/`, managed). Plugin agents ignore that field, so jarx
  lists it there but marks it "not loaded". Transports
  `stdio`, `http` (alias `streamable-http`), `sse` (deprecated, still
  supported by jarx) and `ws`.
- **Instruction files:** managed `CLAUDE.md`, `~/.claude/CLAUDE.md`, project
  `CLAUDE.md` and `.claude/CLAUDE.md`, `CLAUDE.local.md`,
  `.claude/rules/**/*.md`, `~/.claude/rules/`, and `@path` imports up to 4
  hops. `AGENTS.md` when no CLAUDE.md exists. Claude loads these from every
  **parent folder** of the cwd at launch (concatenated root down) and from
  **subfolders** on demand, so jarx collects both.
- **Auto memory:** `~/.claude/projects/<project>/memory/`, keyed by the git
  repo so worktrees share one dir. Moved by `autoMemoryDirectory`, turned off
  by `autoMemoryEnabled`. Subagent memory in `~/.claude/agent-memory/`,
  `.claude/agent-memory/` and `.claude/agent-memory-local/`.
- **Output styles:** `~/.claude/output-styles/` and `.claude/output-styles/`,
  selected by `outputStyle`. They're instructions, so they count as an
  instruction source.
- **Skills, commands, subagents, plugins:** managed, `~/.claude/skills/`,
  `.claude/skills/`, nested `.claude/skills/`, plugin `skills/`, legacy
  `.claude/commands/`, agents dirs, `~/.claude/plugins` and
  `installed_plugins.json`, `enabledPlugins`, marketplaces.
- **Hooks:** all settings scopes, plugin `hooks/hooks.json`, skill and
  subagent frontmatter. All handler types (`command`, `http`, `mcp_tool`,
  `prompt`, `agent`).
- **Agent login:** `~/.claude/.credentials.json` existence only. On macOS
  jarx reports that Claude may use the Keychain but never queries it.

### Codex CLI

- **Config:** `CODEX_HOME` (default `~/.codex`), user `config.toml`, project
  `.codex/config.toml` from root down to cwd (trusted projects only), profile
  files `$CODEX_HOME/<name>.config.toml`, `/etc/codex/config.toml`, managed
  `requirements.toml` (`/etc/codex/` or `%ProgramData%\OpenAI\Codex\`), legacy
  `managed_config.toml`.
- **Precedence:** legacy `managed_config.toml` (applied at startup, above
  even CLI flags) > CLI > project > profile > user > cloud-managed > system >
  defaults. Trust comes from `[projects."<path>"] trust_level`. Project files
  load from the project root marker (`.git` by default, or
  `project_root_markers`) down to the working dir, closest first, and only in
  trusted projects. A profile file applies only with `--profile <name>`, and
  `[profiles]` tables or a `profile` key in `config.toml` are ignored.
  `requirements.toml` constrains values instead of setting them.
- **Silent overrides to watch:** `sandbox_mode` in any loaded layer makes
  Codex ignore `default_permissions` (unless managed
  `allowed_permission_profiles` is set), and permission profiles merge by
  name, so a trusted project can change your profile without restating it.
- **MCP:** `[mcp_servers.<id>]` with `enabled`, `enabled_tools`,
  `disabled_tools`, stdio and streamable HTTP fields, and the admin allowlist
  in `requirements.toml`.
- **Sandbox and approvals:** `sandbox_mode`, `approval_policy`,
  `approvals_reviewer`, `sandbox_workspace_write.*`, `default_permissions` and
  `[permissions.<name>]` profiles, per-tool MCP `approval_mode`.
- **Instruction files:** global and project `AGENTS.override.md`,
  `AGENTS.md`, `project_doc_fallback_filenames`, the `project_doc_max_bytes`
  cap. One file per dir, the first non-empty one, from the project root
  down. The docs describe the cap two ways (a combined budget in the
  AGENTS.md guide, a per-file limit in the advanced config page), so jarx
  marks a file off only when the per-file reading cuts it and notes what
  the combined reading would cut. The rules always read the whole file.
  Project files load only in a trusted project. The AGENTS.md guide doesn't
  say so, but the Codex 0.150.0 changelog (2026-08-26) does: "Untrusted
  projects no longer supply project-level `AGENTS.md` instructions." The
  global file loads either way.
- **Skills and hooks:** `.agents/skills` from the working dir up to the repo
  root, `$HOME/.agents/skills` (`HOME`, not `CODEX_HOME`),
  `/etc/codex/skills`, all documented `hooks.json` locations and inline
  `[hooks]`. Codex runs a non-managed hook only after you review and trust
  it in `/hooks`; jarx notes that it can't see whether you did.
- **Agent login:** `$CODEX_HOME/auth.json` existence only, plus the
  `cli_auth_credentials_store` setting.

### Agent installs and versions

- Find every install of each agent (npm global, native installer, others in
  documented locations). Mark the one that wins on PATH.
- Read the version from disk first (package.json, version dirs, config
  fields). Only run `--version` on a binary that resolves to a known install
  location. Otherwise report "version unknown".
- Check each install against an embedded advisory list (see
  [Advisory data](#advisory-data)).

## Project discovery

- From the agents' own records: the paths in the `projects` map of
  `~/.claude.json` (moved by `CLAUDE_CONFIG_DIR`), Codex `[projects]` trust
  entries in `$CODEX_HOME/config.toml`, and session cwds.
- The folder names under `~/.claude/projects/` aren't used as paths. The docs
  don't describe how they're named, and the observed naming (path separators
  become dashes) can't be turned back into a path without guessing. Session
  history (phase 6) reads the real `cwd` from the transcripts in those folders
  instead, as an observed format.
- Extra paths given to `jarx scan [path...]` are scanned for that run only.
- Plus paths the user adds with `jarx setup repo add` or the dashboard.
- jarx doesn't crawl the whole disk.
- A recorded project that no longer exists on disk shows as **stale**, not as
  an error. Under `--home`, a recorded path outside the fake home shows as
  **outside fake home** and is never read.
- `~/.claude.json` holds history, so it can be large. jarx streams it, keeps
  only the keys of `projects`, and drops every value as it goes, so things
  like an MCP server's env token are never kept.
- A record file jarx can't parse is an info finding that names the file and
  line. It never quotes the content, since a parser error can echo a secret.

### Walking a repo

Inside a project, jarx lists files with a hardened `git ls-files` (tracked
plus untracked, not ignored) so it sees what the agent sees in a normal repo.
The repo's own git config can't make git run anything or list another folder
(see [design.md](design.md)). If the folder isn't a git repo, git refuses, or
git isn't installed, it falls back to its own walk. Under `--home` it always
uses its own walk. Both use a skip list (`node_modules`, `.git`, `vendor`,
build output dirs) that still keeps agent files inside those dirs. jarx lists
up to 200,000 files per project, and a project with more gets an info
finding instead of being cut off silently. Instruction files in parent
folders above the repo root are collected separately, since Claude loads
them too.

## MCP probing

Probing is **on by default**. It adds no new risk, because jarx only starts
what the agent itself would start next session anyway.
`--no-probe` turns it off.

### Which servers get probed

A server is probed only if the agent would start it:

- **Claude, project `.mcp.json`:** enabled through `enableAllProjectMcpServers`
  or `enabledMcpjsonServers` in a file that's honored for that key (user,
  managed, `--settings`, or a trusted local file), or approved in the observed
  state in `~/.claude.json`. It must also not be in `disabledMcpjsonServers`
  anywhere.
- **Claude, all scopes:** respect `enabledMcpServers`/`disabledMcpServers`,
  managed `allowedMcpServers`/`deniedMcpServers`, `allowManagedMcpServersOnly`
  and `managed-mcp.json` exclusive control.
- **Codex:** project servers only in trusted projects. Skip `enabled = false`.
  Respect `enabled_tools`/`disabled_tools` when showing tools. Respect the
  `requirements.toml` allowlist.
- Anything else shows as **"approval unknown, not probed"**. It's never
  started.

### What gets skipped

- Remote servers on plain `http://` URLs. Plain `http://` to a loopback
  address (`127.0.0.0/8`, `::1`, or a name that resolves to one) is allowed,
  since that traffic never leaves the machine.
- OAuth servers (`auth = oauth|chatgpt`, or Claude servers set up for OAuth).
- Servers that use `headersHelper` or `http_headers_helper`, since running the
  helper means running a command. These show as **"requires auth"**.

### How a stdio server is started

- The env is exactly what the config declares, expanded from the user's real
  env the same way the agent does it, plus a small platform baseline so
  launchers work (`PATH`, `HOME`/`USERPROFILE`, `SystemRoot`, `TEMP`,
  `APPDATA` and the like). Nothing else from jarx's own env.
- Claude expansion rules: `${VAR}` and `${VAR:-default}`; an unset var with no
  default stays as literal text; an empty string counts as set.
- Send `initialize`, then `tools/list`, `prompts/list`, `resources/list`. Then
  kill the whole process tree (on Windows, a job object, so `npx` children die
  too).
- 15s timeout per server, at most 4 at a time.
- A failure shows as **"failed to start"** or **"timed out"** (see
  [Server status](#server-status)), with stderr captured and masked.

### How a remote server is probed

- `https://` servers with no creds get one anonymous `initialize` plus the
  list calls. A `401` or `403` shows as **"requires auth"**.
- Servers with static creds configured (a token in `headers`,
  `http_headers`, `env_http_headers` or `bearer_token_env_var`) get them sent
  exactly the way the agent would send them. It's the same no-new-risk logic
  as stdio env expansion: the agent sends these next session anyway. A `401`
  or `403` then shows as **"credential rejected"**.
- For Claude, credential vars in a remote `url` and `headers` read as empty,
  exactly like Claude does: `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`,
  `AWS_BEARER_TOKEN_BEDROCK`, `HTTPS_PROXY`, `NPM_TOKEN` and the rest of the
  documented list, with `:-default` ignored on them. `ANTHROPIC_BASE_URL`
  still expands.
- No redirects. A redirect shows as **"blocked"**.
- Probes never go through a proxy. They ignore `HTTPS_PROXY` and friends and
  connect directly, because through a proxy jarx can't check the address it's
  really talking to. Behind a corporate proxy, remote servers show as
  **"unreachable"**.
- Link-local addresses and cloud metadata endpoints are blocked, checked at
  dial time after DNS so rebinding can't get around it. Blocked: 169.254.0.0/16,
  fe80::/10, `169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`
  and similar. Localhost and private ranges are allowed.
- Transports: streamable HTTP and the old SSE transport.

### The MCP client

jarx has its own list-only MCP client, not the official SDK. The client has no
code path that can send `tools/call` or `resources/read`, and a test proves
the request builder rejects them.

### Server status

Every server ends up with exactly one status:

| Status | Meaning |
|---|---|
| listed | probe worked, tools, prompts and resources are shown |
| missing credential | a referenced env var isn't set, so the agent would start it broken too |
| failed to start | the process exited or the command wasn't found |
| timed out | no answer within 15s |
| not started | the agent wouldn't start it (disabled, not approved, untrusted project, `--no-probe`) |
| insecure transport | plain `http://` URL that isn't loopback, skipped |
| requires auth | OAuth, a headers helper, or a `401`/`403` with no creds sent |
| credential rejected | a `401`/`403` after sending the configured static creds |
| blocked | a redirect, or a link-local or metadata address |
| unreachable | DNS, connect or TLS failure |

### Capability view

For each tool, jarx shows three layers side by side:

1. **Offered by the server:** the tool, its schema and annotations, from the
   probe.
2. **Allowed by the token:** what the server's credential can do. This is
   usually unknown and shows as "unknown". jarx never calls anything to find
   out.
3. **Allowed for the agent:** whether the agent can call it, from permission
   rules (`mcp__server__tool` allow/ask/deny), Codex `enabled_tools`,
   `disabled_tools` and per-tool `approval_mode`, plus the observed modes.

The point is to make "the agent can call a delete tool without asking" easy to
spot.

## Credentials

### What jarx checks

| Kind | Examples | What jarx reads |
|---|---|---|
| `.env*` files in projects | `.env`, `.env.local` | key names only, never values |
| Ambient CLI creds | `~/.aws`, `~/.ssh`, gh, gcloud, azure, docker, netrc | existence plus safe metadata |
| Agent login files | `~/.claude/.credentials.json`, `$CODEX_HOME/auth.json` | existence only |
| OS keychain | any other app's entries | never touched |
| Secrets inline in config | API key in an MCP `env` block, token in a URL | detected, masked |

Safe metadata means things like AWS profile names, the gh host and user, or
whether an ssh key has a passphrase. Where a non-secret file exists, jarx
reads that one instead (`~/.aws/config` over `credentials`, gh `hosts.yml` for
host and user only).

When jarx has to open a secret-bearing file for metadata, it streams it, keeps
only the allowed fields (section names, key names, cipher or kdf names) and
drops everything else right away. A test feeds a fake secret through every
parser and asserts it never shows up in any output, log or snapshot.

### The credential view

Each credential gets one top-level state per project, built from the
per-channel verdicts below:

- **sees:** the secret is already in the agent's context, for example
  pasted into a CLAUDE.md, a memory file or session history. Nothing has to
  be read.
- **can read:** at least one channel can read it (silently, with approval,
  or by the process).
- **can use:** an MCP server holds the token, so the agent can use it through
  the server's tools without ever reading it.
- **not reachable:** every channel is blocked and nothing holds it.

A credential can be in more than one state (for example, both can read and
can use). The view shows the worst one first.

### Reachability verdicts

For every credential location, jarx gives a verdict **per project, per
channel**:

- **blocked**
- **needs approval**: the agent has to ask first
- **readable silently**
- **readable, deny is bypassable**: a rule exists, but the channel can get
  around it
- **readable by the process**: the channel runs with the user's full rights
  outside any sandbox

Each verdict comes with a "why" trail naming the rule and file that decided
it.

### Claude Code channels

1. **File tools (Read, Edit):** permission rules (deny > ask > allow, first
   match wins), `additionalDirectories`,
   `permissions.blockReadsOutsideWorkingDirectories`, trust state for project
   allows.
2. **Bash and PowerShell:**
   - A built-in set of read-only commands, including `cat`, runs with no
     prompt in every mode, except where
     `blockReadsOutsideWorkingDirectories` applies. So with no sandbox and no
     `Read()` deny, a cred file is **readable silently**.
   - A `Read()` deny catches simple commands like `cat` and redirects but not
     `grep -r` or scripts that open files themselves. Without a sandbox that's
     **readable, deny is bypassable**.
   - With the sandbox on, `sandbox.filesystem.denyRead`/`allowRead` and
     `sandbox.credentials.files` deny entries decide. The default sandbox read
     policy allows `~/.ssh` and `~/.aws/credentials`, so a sandbox with no
     `denyRead` protects nothing.
   - Even with the sandbox on and a `denyRead`, a command can be retried
     unsandboxed with `dangerouslyDisableSandbox` after approval, unless
     `allowUnsandboxedCommands` is `false`. So that's **needs approval**, not
     blocked.
   - Commands matching `excludedCommands` always run unsandboxed.
   - Native Windows has no sandbox. There, jarx treats the sandbox as off and
     adds an info finding.
3. **Env vars:** Bash inherits the env secrets Claude Code has, whatever the
   file rules say. The only things that change this are `sandbox.credentials`
   env var entries (sandboxed commands only) and
   `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` (all subprocesses). jarx lists the names
   of secret-looking env vars it can see and gives each one a verdict.
4. **MCP servers:** local servers run outside the sandbox with the user's
   rights. **readable by the process**.
5. **Hooks:** same, **readable by the process**, listed as their own channel.

### Codex channels

1. **Shell and apply_patch:** the docs don't say `read-only` limits reads, so
   paths count as readable unless a `[permissions.<name>]` profile with a
   `filesystem` deny covers them. Protected paths under writable roots (`.git`,
   `.codex`, `.aws`) are about writes, not reads.
2. **Legacy override:** if `sandbox_mode` shows up in any loaded config, comes
   in via `--sandbox`, or is set by the selected profile, Codex uses the
   legacy sandbox settings and ignores `default_permissions`. jarx resolves
   verdicts the same way and flags it (rule `JARX-CODEX-*`).
3. **MCP servers and hooks:** **readable by the process**.

### Observed modes change the verdict

Settings say what could happen. History shows what you actually ran. For each
project, jarx looks at the last 30 days of sessions. If **more than half** ran
in a mode where something other than you approves, then **needs approval**
also shows as **effectively readable**. The configured verdict stays next to
it, and the why trail says something like "14 of 20 sessions in bypass".

Modes that count:

- **Claude:** `auto` and `bypassPermissions` count on every channel.
  `acceptEdits` counts for the edit channel only. `default`, `plan` and
  `dontAsk` don't count (`dontAsk` denies anything not pre-approved).
- **Codex:** `approval_policy = never` and `approvals_reviewer = auto_review`
  count on every channel. Per-tool MCP `approval_mode = approve` or `auto`
  counts for that server's channel only.

## Session history

On by default, `--no-history` turns it off. It's used for three things:

1. **Discovery:** project cwds, and the MCP servers and tools that were
   actually used.
2. **Leaks:** secrets that ended up in transcripts, Codex history or Codex
   memories. jarx reports the file, line and secret type, masked, never the
   value.
3. **Modes:** the permission and approval modes each project actually ran in
   (see above).

Rules:

- **History never goes to the LLM**, even with `--llm`.
- Snapshots keep only counts and hashes from history, never excerpts.
- Scans are incremental. A per-file cursor stores path, size, mtime, byte
  offset and a hash of the first 4 KB. If the file shrank or the head hash
  changed, it gets rescanned from the start.
- Earlier leak findings carry forward (masked) until the file is gone. Mode
  counts are running tallies per session id.
- SQLite files are opened in place with `mode=ro`, `PRAGMA query_only = 1`
  and a short busy timeout. If one is locked, jarx skips it with an info
  finding. It never copies them, since a copy would put history on disk (see
  [design.md](design.md)).
- JSONL and zstd files are streamed line by line. Files over 200 MB are
  skipped with an info finding.

### Observed formats

The docs don't cover most of this:

- the per-entry `permissionMode` in Claude transcripts (the docs call the
  format internal)
- the Codex `sessions/` folder and its `.zst` rollouts
- the Codex `*.sqlite` files
- per-session approval and sandbox values in Codex
- where Claude stores interactive project MCP approvals

jarx supports these as **observed formats**. The parsers are built from fake
fixtures shaped like real files, tolerate version changes, are labeled
"observed, not documented" in the code and the UI, and fall back to
"unknown" when a field is missing. They never error out.

Fixture shapes for Claude transcripts and Codex rollouts come from our own
format notes in the boughs repo (`docs/format-claude-code.md` and
`docs/format-codex.md`), not from guessing. Two things from those notes
matter here: both agents replay records (Claude inside one transcript, Codex
into a new rollout file), so mode counts dedupe by session, and Codex
rollouts live in `sessions/YYYY/MM/DD/` with the project in
`session_meta.cwd`. Fields those notes don't cover, like the mode fields and
the `.zst` and sqlite files, are built from observed structure and marked as
such in the fixture.

## Detection rules

Rules are written in Go and built into the binary. Each one has an ID like
`JARX-MCP-001`, a severity (critical, high, medium, info), a short reason and
a fix hint. There are no user rule files. We write our own rules and don't
copy other scanners.

### Hidden or tricky text

- `JARX-POISON-001` (high): Unicode tag characters. They spell out ASCII
  that renders as nothing, so the finding shows what they spell. Emoji tag
  sequences, like the England flag, don't count.
- `JARX-POISON-002` (medium): bidi controls, so the text reads differently
  than it looks.
- `JARX-POISON-003` (info): zero-width characters. A BOM at the start of a
  file doesn't count, and neither do joiners inside emoji or scripts that
  need them.
- `JARX-POISON-004` (medium): terminal control sequences, like ANSI escapes
  or a lone carriage return, that hide or rewrite text when it's printed.
- `JARX-POISON-005` (info): an HTML comment the agent reads but a rendered
  view hides. The memory docs say Claude strips block-level comments from
  CLAUDE.md files, so those are skipped. Everything else counts, since the
  docs don't say it's stripped: inline comments, and comments in rules,
  imports, `CLAUDE.local.md`, skills, output styles and AGENTS.md. Comments
  in code blocks and code spans render as code, so they aren't hidden.
- `JARX-POISON-007` (high): the content rules below, found inside hidden
  text: a comment the agent reads, tag characters, or words split by
  zero-width characters. A hit there is this rule, not the visible one.

### What the text rules run on

The hidden-text and poisoned-content rules (the "poison engine") run on
**every text the agent reads**, not only tool descriptions:

- instruction files (CLAUDE.md, rules, AGENTS.md, imports, output styles)
- memory files (Claude auto memory, agent memory, Codex memories)
- skills and commands
- hook commands and hook scripts
- every MCP field: server `instructions`, tool names, descriptions, input
  schemas including param names, descriptions, enums and defaults,
  annotations, prompts and their arguments, and resource names and
  descriptions

### Poisoned content

- `JARX-POISON-006` (medium): text aimed at the agent that works against
  you: overriding its other instructions ("ignore your previous
  instructions"), keeping things from you ("don't tell the user"), doing
  things on the quiet, or "before using any other tool". "Don't deploy
  without telling the user" is the opposite, so a negated sentence doesn't
  count. English phrases only.
- `JARX-POISON-008` (medium): exfil shapes: download-then-run (`curl | sh`
  and the PowerShell forms), a send tool used on a credential file,
  encode-and-send instructions, and base64 blobs of 200 chars or more.
- `JARX-POISON-009` (info): pointers to credential and key files (`~/.ssh`,
  `.aws/credentials`, `.env`, `.netrc` and the like). `.envrc` doesn't count.
- Annotations that lie, like a delete tool marked `readOnlyHint`.
- Tool shadowing: two servers exposing the same tool name.

### Hooks

- `JARX-POISON-010` (info): network calls, including every http hook.
- `JARX-POISON-011` (high): download-then-execute. In a hook it's this rule,
  not `JARX-POISON-008`.
- `JARX-POISON-012` (high): writes to shell rc or startup files (`.bashrc`,
  `$PROFILE`, crontab, launch agents, the Windows Run key and the like).
  Reading one doesn't count.
- `JARX-POISON-013` (medium): running a program from a temp dir. A project's
  own scripts don't count, even when the project is cloned into a temp dir.

### Skills

- A skill or command whose body runs shell commands before the agent sees
  it (Claude's `` !`cmd` `` and ` ```! ` blocks), unless
  `disableSkillShellExecution` turns that off.
- A repository skill that pre-approves tools (`allowed-tools`) or adds
  hooks. Claude applies both even in a folder you haven't trusted.

### MCP supply chain and config

- Unpinned `npx`/`uvx` (`@latest` or no version).
- Docker images on `latest`.
- `sh -c` style commands.
- Binaries in temp or download dirs.
- Server commands that install from a git branch ref (`git+https://...#main`,
  `github:owner/repo` with no pinned commit), since the code can change under
  the same config.
- Server commands that run a script from inside the repo (`node ./scripts/x.js`,
  `python tools/server.py`). Anyone who can push to the repo controls that
  server.
- Codex `env_vars` forwarding secret-looking vars into a server.
- Plain `http://` remote URLs.
- Tokens in the URL.
- Secrets in headers.
- Forwarding the whole env.
- `headersHelper` / `http_headers_helper` (runs a command at connect).
- Broad filesystem args (a server given `/` or `~`).

### Permissions and auto-approval

- `bypassPermissions`, `Bash(*)`, `danger-full-access`,
  `approval_policy = never`.
- `enableAllProjectMcpServers`, Codex per-tool `approval_mode = approve`.
- Allow rules covering credential paths.
- Codex `sandbox_mode` silently overriding permission profiles: high when a
  project file does it (a repository turning off your deny rules), medium
  when it's your own layers.
- A trusted project changing a Codex permission profile another layer
  defines.
- A legacy Codex `managed_config.toml` overriding your config and CLI flags,
  and legacy `[profiles]` tables Codex ignores (info).
- A repository changing which instructions Codex loads, through
  `project_doc_max_bytes` or `project_doc_fallback_filenames`.

### Repo-level red flags

- A repo setting the model endpoint or token (for example
  `ANTHROPIC_BASE_URL` or an auth token in project `env`, or a Codex
  `model_provider` base URL in project config).
- TLS checks turned off.

### Secrets

- Inline secrets found by token format, from the provider's own docs or an
  RFC, plus a name rule. The formats ship as an embedded data file with an
  "as of" date and a source per row. The first cut covers about 20 formats
  devs most often hold keys for; the PRD's target is 30 to 50.
- The **name rule** masks a value assigned to a name that says it's a
  secret (`*_TOKEN=`, `"api_key":`, `password:`), whatever the value looks
  like. It catches values with no documented format, like npm, OpenAI and
  Hugging Face keys, and the demo's made-up fakes. References (`$X`,
  `${X}`), booleans, short numbers and names that describe a secret instead
  of holding one (`apiKeyHelper`, `token_path`) are left alone. A known
  format wins over the name rule.
- It runs on config files and also on instruction, memory, skill and hook
  files. A secret found in an instruction or memory file means the agent
  **sees** it (see [The credential view](#the-credential-view)).
- Three rules, each reported once per file:
  - `JARX-SECRET-001` (high): a secret in text the agent loads (instruction
    files, imports, memory, skill bodies), so it's already in context.
  - `JARX-SECRET-002` (medium): a secret written in a config file, a hook
    command or a hook script.
  - `JARX-SECRET-003` (info): a match that looks like a placeholder, like
    `your-api-key-here`. It's still masked.
- Each finding says how many other files hold the same fingerprint.
- A found secret is replaced with `REDACTED:<type>` (for example
  `REDACTED:github_pat`) everywhere it would appear.
- Each secret also gets a **fingerprint**: a keyed hash (HMAC with a random
  per-install key stored in jarx's config dir) cut to a short id. The same
  key showing up in two places gets the same fingerprint, so jarx can say
  "this token is in your `.mcp.json` and in 3 session files" without showing
  it. The per-install key means fingerprints can't be brute-forced from a
  snapshot alone.

### Exposure, drift and versions

- A credential readable silently on any channel (from the verdicts).
- **Drift:** when a tool description's hash changes, that tool goes through
  the poison rules again. It isn't just flagged as "changed".
- **Vulnerable agent version:** an install whose package name and version fall
  in an advisory's affected range.

### Vendor badge

A hand-curated embedded list of the top 20 MCP vendors gives an **official**
or **community** badge. The badge is display only and never changes how a
server is treated.

The list is seeded from the official MCP registry at build time (by a dev
script, never by jarx at runtime). A registry entry is only taken when its
namespace matches the vendor's own domain (for example `com.stripe/*` for
stripe.com). Everything else is hand-checked before it goes in.

## Built-in tools catalog

jarx ships an embedded catalog of each agent's built-in tools, taken from the
vendor docs (the Claude Code tools reference and the Codex docs). For each
tool it records what it does, whether it prompts by default, and which
channel it belongs to. The channel verdicts and the effective permissions view
use it.

The catalog is stamped with the agent version it was built against. If an
installed agent is newer than that, jarx shows a warning that the agent may
have tools the catalog doesn't know about.

## Effective permissions view

Per project, jarx shows every permission rule that applies, after merging:

- the rule itself (`Read(~/.aws/**)`, `Bash(git *)`, `mcp__github__*`,
  `sandbox.filesystem.denyRead`, Codex `[permissions.<name>]` entries and so
  on)
- allow, ask or deny
- which file it came from and which scope (managed, CLI, local, project,
  user, profile, requirements)
- whether it's in effect, and if not, why (for example "project allow waits
  for trust", "ignored from project files", "overridden by legacy
  `sandbox_mode`")

## Where your agent talks to

A dashboard panel and a CLI section, per project and per agent:

- **Model endpoint:** the base URL in use (Claude `ANTHROPIC_BASE_URL` and the
  other provider vars from the env-vars docs; Codex `model_provider`,
  `model_providers.<id>`, `openai_base_url`, `chatgpt_base_url`) and which
  file set it.
- **Auth source:** login file, `apiKeyHelper`, env var name, keychain (named
  only, never read), Codex `cli_auth_credentials_store`.
- **Proxies:** proxy env vars and settings, Codex `features.network_proxy`.
  When a proxy is set, the panel says "proxy set, probes went direct".
- **TLS:** custom CA settings and anything that turns TLS checks off.
- **MCP hosts:** every remote MCP host with its status.
- **Network domains:** sandbox `allowedDomains`/`deniedDomains`, `WebFetch`
  rules, Codex permission profile `network.domains` and `network_access`.
- **Codex web search:** the `web_search` mode (`disabled`, `cached`, `live`,
  `indexed`) and any `allowed_web_search_modes` requirement.

## Optional LLM review

Off unless the user sets it up. Without it, jarx is rules only.

`jarx setup llm` (or the dashboard) asks for a base URL, model and key. Any
OpenAI-compatible endpoint works. The key goes in the OS keychain under jarx's
own entry, or the user gives an env var name to read it from. jarx never picks
up keys from the env on its own. On headless Linux with no Secret Service,
only the env var option is offered.

The review runs only on `jarx scan --llm` or the dashboard button. Before
sending anything, jarx shows how many artifacts it will send, roughly how many
tokens, and to which host.

The LLM sees one artifact at a time: a tool's name, description and schema, a
skill, an instruction file, or a hook command. It checks whether what the
artifact tells the agent to do goes past its stated purpose. Every finding has
to quote evidence, and code checks that the quote really appears in the input
that was sent. A finding without a matching quote gets dropped.

Secrets are masked before anything is sent, using the same `REDACTED:<type>`
format, and history is never sent. A canary test plants fake secrets in every
artifact kind, runs the LLM step against a fake endpoint, and asserts that no
canary appears in any request body.

The LLM has to answer in a fixed JSON shape. jarx validates it. If it's
invalid, jarx retries once with the validation error included, and if the
retry fails too, that artifact gets an "LLM review failed" info finding
instead of guessed results.

Results are cached by content hash, so an unchanged artifact isn't sent twice.

## Snapshots and diff

- Every `jarx scan` saves a masked JSON snapshot. jarx keeps the last 20.
- `jarx scan` always shows the diff against the previous snapshot. It covers:
  projects, servers, tools, prompts, resources, hooks, skills, instruction
  files, permission changes, verdict changes and tool description hash
  changes.
- To compare against an older snapshot, use the snapshot picker in the
  dashboard.
- Named baselines are for later.

## CLI

The CLI stays small: three commands and a version flag.

| Command | What it does |
|---|---|
| `jarx scan [path...]` | full scan, prints a summary grouped by severity plus what changed since the last scan. Extra paths are scanned for this run only. |
| `jarx ui` | start the dashboard |
| `jarx setup` | show jarx's own settings: extra repo paths, and whether the LLM is set up |
| `jarx setup repo add\|rm <path>` | add or remove an extra project path |
| `jarx setup llm` | set base URL, model, and key or env var name |
| `jarx --version` | print version and advisory data date |

Flags:

| Flag | On | What it does |
|---|---|---|
| `--home <dir>` | `scan`, `ui`, `setup` | treat `<dir>` as the home dir instead of the real one (see [Demo home](#demo-home)) |
| `--no-probe` | `scan` | skip MCP probing |
| `--no-history` | `scan` | skip session history |
| `--llm` | `scan` | run the LLM review after showing the preview |

### Demo home

`--home <dir>` points `jarx scan`, `jarx ui` and `jarx setup` at a fake home. Everything
jarx would read from the real machine comes from inside `<dir>` instead:
agent config dirs, project records, history, cred locations, and jarx's own
state (snapshots, cursor, cache), so demo runs never mix with real ones.
jarx's state goes in `<dir>/.jarx-state/`, which the repo's `.gitignore`
ignores under `testdata/`, so demo runs never dirty the repo. With
`--home`, jarx doesn't read managed policy dirs, the Windows registry, macOS
plists, the real env or the real PATH. Env vars for the env var channel come
from `<dir>/.jarx-env` instead. Absolute paths inside the fake home's agent
records are read relative to `<dir>`, so `/projects/app` in the demo's
`.claude.json` means `<dir>/projects/app` on any machine.

The repo ships `testdata/demo/`, a fake home with planted problems:

- a CLAUDE.md with hidden unicode and an HTML comment aimed at the agent
- a skill with injection text
- a fake `.env` (values are obviously fake, like `sk-demo-0000`)
- a risky `.mcp.json` with an unpinned `npx` server, a token in a URL and a
  server whose tools have poisoned descriptions (served by a small fake MCP
  server built from the repo, so probing it is safe)
- settings with `bypassPermissions` and a broad `Bash(*)` allow

Demos, screenshots and docs always use `jarx ui --home testdata/demo`, never
a real machine.

## Dashboard

- `jarx ui` binds `127.0.0.1` on a random port and prints a URL with a
  one-time token.
- It checks the `Host` header to block DNS rebinding and sends no CORS
  headers. Every asset is embedded in the binary, so nothing loads from a CDN.
- Pages are server-rendered with Go `html/template`, plus a bit of vanilla JS
  and one CSS file. The build doesn't need npm.
- Shows the same data as the CLI: projects, servers with status, the
  capability view per tool, the credential view and per-channel verdicts,
  effective permissions, where your agent talks to, findings, the unknown
  settings report, and what changed.
- **Write actions** (POST only, token plus `Origin` check):
  - add or remove a repo path
  - set the LLM config and key. The key is write-only, and the page only ever
    shows "set" or "not set".
  - rescan
- A pasted repo still only probes servers the agent would start.
- Never writes agent config.

## Network calls

This is the full list. Anything not here is a bug.

| When | What | To where | Turned off by |
|---|---|---|---|
| `jarx scan` with probing (default) | MCP `initialize` and list calls to remote servers that would connect anyway, with their configured static creds if any | the server's configured `https://` URL | `--no-probe` |
| `jarx scan` with probing (default) | jarx starts stdio servers. **The servers themselves** may use the network (for example `npx` downloading a package), just like when the agent starts them | whatever the server does | `--no-probe` |
| `jarx scan --llm` or dashboard button | LLM review requests, redacted | the base URL the user set up | don't pass `--llm` |
| `jarx ui` | listens for the browser | `127.0.0.1` only, inbound | not running `jarx ui` |

Rules for every outbound call jarx makes itself:

- Plain `http://` is only ever used for loopback. Every other `http://` URL
  is never called. The loopback check runs on every connection, after DNS, so
  a name that later resolves somewhere else is still refused.
- No redirects.
- Link-local and cloud metadata addresses are blocked at dial time.
- No proxy. Probe traffic connects directly, so the dial-time check sees the
  real address.
- A hostile server can't stall jarx or fill its memory: a response body is
  capped at 10 MiB, headers at 64 KiB, and a whole request at 20s. jarx never
  asks for compressed responses, so nothing inflates behind the cap.
- There's no telemetry, update check, advisory download, vendor list download
  or crash reporting.

With `--no-probe` and no `--llm`, jarx makes zero network calls.

## What jarx writes to disk

Everything lives under `os.UserConfigDir()/jarx/` (or `<home>/.jarx-state/`
with `--home`):

- `config.json` with the extra repo paths from `jarx setup repo add`, and
  later the LLM base URL, model and key env var name (never the key). It has
  a version number; a config from a newer jarx is refused, not guessed at.
  Reading it never creates the state dir, so a scan that saves nothing writes
  nothing.
- `fingerprint.key`, the random per-install key behind secret fingerprints.
  It's made the first time a secret is found, and a damaged one is reported,
  never replaced.
- `snapshots/` with the last 20 masked snapshots
- the history cursor (no content)
- the LLM cache (hash to result)

jarx writes nothing anywhere else.

## Advisory data

- An embedded, hand-curated list of known vulnerabilities for Claude Code and
  Codex, built from the official GitHub security advisories for both repos.
- Matching is by package name plus version range.
- Only as fresh as the jarx build. The dashboard and `jarx --version` show
  "advisory data as of <date>".

## Architecture

Three layers:

1. **Agent adapters**, one per agent (Claude Code, Codex). Each one knows that
   agent's paths, file formats, precedence and quirks, and turns them into the
   shared model. Nothing outside an adapter knows agent-specific file layouts.
2. **One agent-neutral model:** projects, instruction sources, memory,
   skills, hooks, MCP servers and tools, permission rules, sandbox settings,
   network settings, credentials, installs and sessions. **Every setting keeps
   where it came from:** file, scope, line where possible, and whether it's in
   effect.
3. **Shared analyzers** that only read the model: poison engine, secret
   scanner, reachability verdicts and the credential view, capability view,
   effective permissions, network panel, drift and the version check.

Adding an agent later means writing an adapter. The analyzers stay the same.

### Unknown settings report

Each adapter knows the keys it understands. Any key it doesn't recognize gets
listed in an unknown settings report with its file and scope, so a new agent
release can't silently add a setting jarx ignores. Unknown keys are info
findings, never errors.

### Fixtures per agent version

Test fixtures are fake config trees organized by agent version (for example
`testdata/claude/<version>/`, `testdata/codex/<version>/`), including the
observed history formats. When a new agent version changes a format, it gets
a new fixture dir and the old ones keep passing.

## Dependencies

Approved for v1:

- `github.com/BurntSushi/toml`: Codex config
- `github.com/zalando/go-keyring`: jarx's own LLM key
- `github.com/klauspost/compress`: zstd Codex session files
- `modernc.org/sqlite`: Codex sqlite files, pure Go
- `golang.org/x/sys`: Windows job objects for probe process trees

Everything else is stdlib (`net/http`, `html/template`, `embed`, `log/slog`,
`os/exec`). There's no CLI or web framework, and the MCP client is our own.

## Testing and done criteria

v1 is done when all of these pass:

1. **Speed:** a full scan with probing on a machine with about 20 projects and
   10 MCP servers takes under 30s, not counting time spent waiting on probe
   timeouts.
2. **No leaks:** a planted fake secret suite proves no fake secret reaches the
   terminal, dashboard, snapshots, logs or the LLM payload.
3. **Detection:** a fixture corpus of known poisoned artifacts gets 100%
   detection, and a clean corpus gives zero high or critical findings.
4. **Dashboard security:** no token, a bad Host and a bad Origin all get
   rejected, and write endpoints reject GET.
5. **MCP client:** a test proves it can't send `tools/call` or
   `resources/read`.
6. **LLM canary:** fake secrets planted in every artifact kind never show up
   in an LLM request body.
7. **Probe network rules:** tests cover blocked redirects, blocked link-local
   and metadata IPs, and skipped `http://` URLs.
8. **Cross-platform:** CI runs on Windows, macOS and Linux.

Tests use fake fixtures only, never real config from a dev machine. All
features follow TDD. Every detection rule ships with its own poisoned and
clean fixtures, written by us as the failing test before the rule exists.

## Limits

Things jarx can't see, stated plainly in the README and the dashboard:

- **claude.ai cloud connectors.** They're set up in the claude.ai account,
  not on disk, so jarx can't list them. It notes that they may exist.
- **`--mcp-config` and SDK-supplied servers.** Servers passed on the command
  line or by an Agent SDK app exist only for that run. jarx can't know about
  them.
- **Other `--settings` / `-c` overrides** passed per run, for the same
  reason.
- **Secrets without a known format or name.** A value with no documented
  format, assigned to a name that doesn't say it's secret, isn't found. A
  Codex config file that isn't valid TOML isn't scanned for secrets.
- **macOS MDM policy for Claude.** Claude's docs name the
  `com.anthropic.claudecode` managed preferences domain, but neither they nor
  Apple's docs say where it sits on disk, so jarx doesn't check it. Managed
  settings files and the Windows registry are still read.
- **Server-managed Claude settings and `policyHelper`.** Remote policy lives
  on Anthropic's servers or a gateway, and a policy helper is a program jarx
  won't run. When a helper is set, jarx says the effective managed settings
  are unknown.
- **WSL inheriting Windows policy.** With `wslInheritsWindowsSettings`,
  Claude in WSL also reads the Windows registry and managed settings file.
  jarx treats WSL as plain Linux and doesn't follow that.
- **What a token is allowed to do** on the server side (layer 2 of the
  capability view), which is usually unknown.
- **Undocumented formats** can change with any agent release. jarx degrades
  to "unknown" there.
- **Hooks in skill and subagent frontmatter** are kept as raw text, not split
  into events and commands, since jarx doesn't parse nested YAML. The rules
  still read the text.
- **Plugins and skills that aren't on disk as records.** `--plugin-dir`,
  `--plugin-url` and SDK plugins (`@inline`), plugins and skills synced from
  claude.ai, and marketplaces jarx would have to fetch aren't listed.
- **Codex settings jarx can't see.** Cloud-managed `config.toml` defaults and
  cloud requirements, macOS managed preferences (`com.openai.codex`), the
  profile a run selects with `--profile`, and which hooks you've trusted in
  `/hooks` (Codex keeps that against each hook's hash, somewhere the docs
  don't name).
- **Comments the docs don't cover.** The memory docs only say block-level
  comments in CLAUDE.md files are stripped. jarx assumes every other comment
  reaches the agent, including in an AGENTS.md that Claude reads. A stripped
  comment still shows when the agent opens the file with its Read tool;
  jarx doesn't flag those.
- **Which Codex version you run.** Codex before 0.150.0 loads a project's
  AGENTS.md even when the project isn't trusted. jarx follows current
  Codex until `analyze/versions` can tell which one is installed.
- **Approval of external imports.** Claude asks before it loads an
  `@import` from a project file that points outside the project, and the
  docs don't say where that answer is kept. jarx lists those imports as
  waiting on approval.
- **Network paths.** jarx never reads a UNC path (`\\host\share`), a
  `/net` or `/Network` path, or a symlink that leads to one, since even a
  lookup can contact the host and, on Windows, send it your NTLM hash.
  Claude doesn't follow those links either.
- **Static analysis only.** Verdicts come from settings and docs, not from
  testing the agent.

## Later

- CI gate: exit codes, JSON and SARIF export.
- Named baselines (`jarx baseline`).
- Typosquat and lookalike detection.
- Behavior evidence from history (file reads, network calls by tools).
- Cross-artifact LLM review.
- Release binaries.
- More agents.
- Agent files shipped inside dependencies. npm packages can ship their own
  `CLAUDE.md` or `AGENTS.md` inside `node_modules`, which is a supply chain
  angle worth checking.

## Open items to check during implementation

- The exact meaning of Codex MCP `approval_mode` values (`auto`, `prompt`,
  `writes`, `approve`). Confirm against the config reference before the mode
  rule ships.
- Codex's env var channel is `shell_environment_policy`, from the advanced
  config docs. `ignore_default_excludes` defaults to `true`, so variables
  named like `KEY`, `SECRET` or `TOKEN` reach spawned commands unless it's
  set to `false`. jarx records it now; the verdict comes with phase 5.
- The Codex sessions path and the shapes of the sqlite and zstd files, as
  observed formats.

## Sources

Official docs, read 2026-11-21. Codex pages now redirect to
learn.chatgpt.com.

- Claude Code: https://code.claude.com/docs/en/settings,
  /settings-reference (read 2026-11-22), /managed-settings, /mcp (including `#credential-variables-that-read-as-empty`),
  /managed-mcp, /permissions (including `#read-only-commands`),
  /permission-modes, /sandboxing, /hooks, /skills, /sub-agents, /memory,
  /plugins-reference, /claude-directory, /authentication, /sessions,
  /tools-reference, /output-styles
- Codex changelog: https://learn.chatgpt.com/docs/changelog (CLI 0.150.0,
  read 2026-11-23)
- Codex: https://developers.openai.com/codex/config-file/config-basic,
  /config-file/config-advanced, /config-reference, /permissions,
  /concepts/sandboxing, /agent-approvals-security, /mcp, /guides/agents-md,
  /skills, /hooks, /auth, /memories, /enterprise/managed-configuration
