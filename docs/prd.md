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
   `server/discover` (or `initialize`, for a legacy server) and the list
   methods.
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
- **Mode locks:** `permissions.disableBypassPermissionsMode` and
  `disableAutoMode` (also accepted as `permissions.disableAutoMode`) work
  from any file, take `"disable"`, and the strictest value wins. A locked
  `bypassPermissions` or `auto` default mode isn't in effect. For auto the
  docs say the session starts in `default`; lower layers don't take over.
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
- Read the version from disk (package.json, version dirs, config fields).
  jarx never runs an agent to ask its version: every install it knows gives
  its version on disk, so `--version` would add a process and tell it
  nothing new. Where the disk doesn't say, it reports "version unknown".
- Check each install against an embedded advisory list (see
  [Advisory data](#advisory-data)).

Where jarx looks, from the docs:

- **Claude Code** (code.claude.com/docs/en/setup): the native installer's
  launcher at `~/.local/bin/claude` (`claude.exe` on Windows) and its
  versions in `~/.local/share/claude/versions`. On macOS and Linux the
  launcher is a symlink to one of those, so the link names the version. If
  it isn't a link and there's one version, that's the version. Otherwise
  it's unknown. The npm package `@anthropic-ai/claude-code` installs the
  same binary.
- **Codex** (the openai/codex README): the npm package `@openai/codex`. The
  standalone installers, Homebrew and release binaries are supported too,
  but no doc says where they put Codex.
- **npm** (docs.npmjs.com, "folders"): the global prefix is
  `npm_config_prefix` when set, else `%AppData%\npm` on Windows and
  `/usr/local` elsewhere. Packages are in `{prefix}/lib/node_modules` (Unix)
  or `{prefix}/node_modules` (Windows). A prefix set in `.npmrc` isn't seen,
  because that file can hold auth tokens and jarx never reads it.
- **PATH:** the first dir with the agent's command wins, trying `PATHEXT`
  in order on Windows. On Unix the file needs an exec bit. Nothing is run.
  An install at a place the docs don't name (Homebrew, WinGet, apt, the
  Codex installers) only shows up this way, as "unknown".

Findings, in the user config group:

- `JARX-VERSION-001` (high), `002` (medium), `003` (info): an install whose
  version is in an advisory's affected range, by the worst advisory. A
  critical counts as high and a low as info. The evidence names the worst
  few and the version that fixes all of them.
- `JARX-VERSION-004` (medium): an older install wins on PATH over a newer
  one, so an update may not have taken.
- `JARX-VERSION-005` (info): the command on PATH is at no install location
  the docs name, so jarx can't tell its version.

Each agent's row in the agents block gets a line with the install that
runs, how many more there are, and "newer than jarx's tool list" when the
version is past the built-in tools catalog. `--all` lists every install.

## Project discovery

- From the agents' own records: the paths in the `projects` map of
  `~/.claude.json` (moved by `CLAUDE_CONFIG_DIR`), Codex `[projects]` trust
  entries in `$CODEX_HOME/config.toml`, and session cwds.
- The folder names under `~/.claude/projects/` aren't used as paths. The docs
  don't describe how they're named, and the observed naming (path separators
  become dashes) can't be turned back into a path without guessing. Session
  history (phase 6) reads the real `cwd` from the transcripts in those folders
  instead, as an observed format.
- A session cwd is a project of that agent's, with the `history` scope and
  marked observed, so a dir you only ever ran an agent in shows up and gets
  verdicts. A cwd inside the agent's own dir (a Codex rollout in
  `CODEX_HOME`) is its internal work, not a project. Each project keeps
  the sessions that ran in it.
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
  managed, `--settings`, or a trusted project or local file). The approval
  dialog writes `enabledMcpjsonServers` to `settings.local.json`. It must
  also not be in `disabledMcpjsonServers` anywhere.
- **Claude, all scopes:** respect the per-project `disabledMcpServers` in
  `~/.claude.json`, `allowedMcpServers`/`deniedMcpServers` merged across
  scopes, `allowManagedMcpServersOnly`, `managedMcpServers`,
  `strictPluginOnlyCustomization` and `managed-mcp.json` exclusive control.
- **Claude, the same name in more than one scope:** only the highest
  definition loads (local, then project, then user, with managed above
  them and plugins matched by endpoint). The others are listed as not in
  effect. When the docs don't say which one loads, every candidate counts
  as one that may start.
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
- Send `server/discover` (or `initialize`, for a server older than the
  2026-07-28 protocol), then `tools/list`, `prompts/list`, `resources/list`.
  Then kill the whole process tree (on Windows, a job object, so `npx` children die
  too).
- 15s timeout per server, at most 4 at a time.
- A failure shows as **"failed to start"** or **"timed out"** (see
  [Server status](#server-status)), with stderr captured and masked.

### How a remote server is probed

- `https://` servers with no creds get one anonymous `server/discover` (or
  `initialize`) plus the list calls. A `401` or `403` shows as **"requires auth"**.
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

Layer 3 is one of: hidden (Codex `enabled_tools` or `disabled_tools`),
denied, asks, may run without asking, or runs without asking, with the rule
or mode that decided it. For Claude, deny beats ask beats allow, and with no
rule the default mode decides (`bypassPermissions` runs it, `dontAsk` denies
it, `auto` leaves it to a classifier, the rest ask). A server name with `__`
in it or ending in `_` is only allowed by the wildcard form. For Codex, the
tool's `approval_mode` or the server's default decides first (`prompt`
asks, `writes` asks unless the tool is marked read-only). With no mode, a
tool marked destructive asks unless it's also marked read-only, and the rest
follow `approval_policy`.

The point is to make "the agent can call a delete tool without asking" easy to
spot:

- `JARX-CAP-001` (high): a tool that changes things (marked destructive and
  not read-only, or named for a change) that an allow rule or Codex approval
  mode lets run without asking. One finding per rule or mode, naming the
  tools it lets through, since that's one fix. A mode alone, like
  `bypassPermissions`, has its own rule (`JARX-PERMS-001`).
- `JARX-CAP-002` (medium): a Codex `approval_mode` or
  `default_tools_approval_mode` of `auto` or `approve`. The docs don't say
  what these do, so jarx says the tool may run without asking.

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

Paths come from each CLI's own docs, including the env vars that move them
(`AWS_SHARED_CREDENTIALS_FILE`, `GH_CONFIG_DIR`, `CLOUDSDK_CONFIG`,
`KUBECONFIG` and the rest), on Windows, macOS and Linux. design.md has the
full table and what jarx keeps from each kind.

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

How jarx tells, for each agent that knows the project:

- **sees** comes from text the agent loads: an instruction file, rule,
  import or output style in effect whose text holds a masked secret. jarx
  never reads credential files, so it names the secret by its kind and
  fingerprint, not by which file it came from. A secret that ended up in
  one of the agent's own sessions there (its transcript or rollout) is
  seen too, as `secret_in_history` with the session's file. Leaks in
  `history.jsonl` or the Codex memories database aren't tied to a project,
  so they stay `JARX-HISTORY-001` findings only.
- **can read** is any channel whose verdict isn't blocked, so approval, a
  bypassable deny and reads by the process all count.
- **can use** is an MCP server the agent would start that gets the
  credential: an env var it references (Claude's `${VAR}` and
  `${VAR:-default}` in env, headers, args or the URL; Codex's `env_vars`,
  `bearer_token_env_var` and `env_http_headers`), or a secret written into
  its own definition, which is its own row.
- **not reachable** is everything else.

The scan shows one line per project, after what the agents load, counting
each state per agent (`credentials: claude 1 sees - 12 can read - 1 can use
- codex 11 can read`). `--all` lists each agent's view in full next to the
per-channel verdicts.

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
   - Who approves the unsandboxed retry depends on the mode and the rules
     (sandboxing docs, "The unsandboxed retry escape hatch"): an allow rule
     matching the command approves it with no prompt, so `Bash(cat *)`
     makes a `denyRead` credential **readable silently**; `bypassPermissions`
     runs it without asking; `dontAsk` denies it; an ask rule for
     `Bash(dangerouslyDisableSandbox:true)` prompts on every retry, in every
     mode.
   - `sandbox.credentials.files` and `envVars` entries can `mask` instead of
     `deny`: sandboxed commands get a stand-in. jarx counts a masked file as
     blocked for reading, with a note that the docs say a mask matching
     nothing leaves the real file readable.
   - `sandbox.filesystem.disabled` (user or managed settings only) turns off
     filesystem isolation, so the sandbox doesn't limit reads.
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

1. **Shell and apply_patch:** the sandbox modes and the built-in profiles
   (`:read-only`, `:workspace`) limit writes, not reads: the docs say even
   `read-only` can "read accessible files", and they don't say a built-in
   limits reads, so jarx counts them as open. A custom
   `[permissions.<name>]` profile reads only what its `filesystem` table
   grants (`:minimal`, the workspace roots, a path, `:root` for broad reads),
   unless it `extends` a built-in. Its `deny` entries block reads, a deny
   wins an equally specific grant, and a narrower path can reopen a broader
   deny. Protected paths under writable roots (`.git`, `.codex`, `.aws`) are
   about writes. Codex has no separate file-read tool; `view_image` only
   reads images.
   - When the sandbox stops a read, Codex can ask to run the command outside
     it. `approval_policy = never`, or granular `sandbox_approval = false`,
     auto-rejects that (**blocked**); `approvals_reviewer = auto_review` has a
     reviewer subagent approve instead of you (**readable silently**);
     otherwise you approve it (**needs approval**). The docs don't give a
     default `approval_policy`, so an unset one counts as `on-request`, the
     interactive default and the worse case.
   - Env vars reach commands through `shell_environment_policy`: `inherit =
     none` or `core` keeps secrets out, `ignore_default_excludes` defaults to
     `true` (so names with KEY, SECRET or TOKEN are kept unless it's
     `false`), and `filters`, `exclude` and `include_only` patterns (case
     insensitive, `*` for any text) drop or keep a name. The highest layer
     that sets any of the lists wins.
   - On native Windows the sandbox covers commands and their child
     processes, but the `unelevated` implementation doesn't support denied
     read paths, and Codex falls back to it when `elevated` setup isn't
     available (Windows sandbox docs). So a profile deny only counts as
     blocking there when `windows.sandbox` pins `mxc` (and requirements don't
     set `windows.allow_mxc = false`), or requirements'
     `windows.allowed_sandbox_implementations` leaves `unelevated` out.
     Otherwise it's **readable, deny is bypassable**.
   - A glob deny is matched when each sandboxed process starts, on every
     platform, so a matching file created later stays readable to a process
     already running. jarx notes this whenever a glob deny decides a
     verdict.
2. **Legacy override:** if `sandbox_mode` shows up in any loaded config, comes
   in via `--sandbox`, or is set by the selected profile, Codex uses the
   legacy sandbox settings and ignores `default_permissions` and every
   profile, `extends` included. jarx resolves verdicts the same way, notes a
   profile deny it drops in the why trail, and flags the switch
   (`JARX-CODEX-001`, `JARX-CODEX-002`).
3. **MCP servers and hooks:** **readable by the process**.

### The mode a session starts in

With no `permissions.defaultMode` in effect, an interactive Claude session
starts in `auto` from 2.1.283 on, unless a settings file sets
`disableAutoMode` to `"disable"`, which makes it `default` (permission-modes
docs, "Which mode a session starts in"; `claude -p` and the Agent SDK start
in `default`). The Claude adapter works out this start mode for every
project, even one with no settings files, and the verdicts and the
capability view use it.

In `auto`, a classifier approves instead of you, so jarx counts what would
need your approval as **readable silently**, and says so in the why trail.
Two things prompt in every mode, `auto` and `bypassPermissions` included:
an explicit ask rule, and reads outside the working directories while
`blockReadsOutsideWorkingDirectories` is on (unsandboxed retries too).
`dontAsk` turns what would ask into **blocked**.

### Observed modes change the verdict

Settings say what could happen. History shows what you actually ran. For each
project, jarx looks at the last 30 days of sessions. If **more than half** ran
in a mode where something other than you approves, then **needs approval**
also shows as **effectively readable**. The configured verdict stays next to
it, and the why trail says something like "14 of 20 sessions in bypass".

- Only the agent's own sessions count, so Codex sessions in a dir don't
  dilute Claude's.
- Under `--home`, the 30 days end at the newest session in the fake home,
  not today: a fake home is a snapshot, and its verdicts shouldn't change
  from week to week. A real scan uses today.
- Only verdicts that need approval change. A block stays a block.
- Each project group gets a `sessions:` line, per agent: how many, how
  many ran in each hands-off mode, and how many are undated (`sessions:
  claude 2 - 1 in bypassPermissions - codex 1 - 1 with
  approval_policy=never`). The `--all` reach rows show the observed
  verdict in parentheses after the configured one.

Modes that count:

- **Claude:** `auto` and `bypassPermissions` count on every channel.
  `acceptEdits` counts for the edit channel only, so it never changes a
  verdict on reading a credential. `default`, `plan` and
  `dontAsk` don't count (`dontAsk` denies anything not pre-approved).
- **Codex:** `approval_policy = never` and `approvals_reviewer = auto_review`
  count on every channel. Per-tool MCP `approval_mode = approve` or `auto`
  counts for that server's channel only. A `granular` policy doesn't count:
  its flags say which prompts are auto-rejected.

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
- A session with no timestamp still counts toward the mode tallies, and
  the line says how many were undated ("14 of 20 sessions in bypass, 2
  undated").
- A session that switched modes counts in every mode it ran a prompt in,
  so one prompt in `bypassPermissions` puts it in "sessions in bypass".
  jarx doesn't guess in the agent's favor.

### Claude history

Where the files are comes from the docs (code.claude.com, "Manage
sessions" and "Explore the .claude directory"):

- Transcripts at `~/.claude/projects/<project>/<session-id>.jsonl`, moved
  by `CLAUDE_CONFIG_DIR`. `<project>` is the cwd with every
  non-alphanumeric turned into `-` (truncated with a hash past 200
  characters), so it can't be turned back into a path. The real cwd comes
  from the records.
- A session's set-aside copies sit next to it
  (`<session>.orphaned-<ts>-<suffix>.jsonl`,
  `<session>.jsonl.superseded-<ts>`). They're the same session, so they
  merge by id.
- `<session>/subagents/` and `<session>/tool-results/` aren't sessions,
  so only top-level files are read.
- `~/.claude/history.jsonl` holds the prompts you typed, with their
  project path. It's read for leaks only.

What's inside is observed: a `permission-mode` record with
`permissionMode` and `sessionId`, and `permissionMode`, `cwd`,
`sessionId` and `timestamp` on prompts. A mode is kept only when it's
letters, and a session id only when it's id characters, so the cursor
can't pick up content through them. A file with no session id takes the
id from its name. Under `--home`, a cwd maps into the fake home like
every other agent record.

Findings:

- `JARX-HISTORY-001` (medium): a secret in session history. The evidence
  is the line, the type and the fingerprint (`line 4: named_secret
  REDACTED:named_secret:<fingerprint>`), plus how many other history files
  hold it. A likely placeholder doesn't count.
- `JARX-HISTORY-002` (info): a history file over 200 MB, not read.

The scanned block gets a `sessions` row with the session and history
file counts, how many are undated, and "observed, not documented".

### Codex history

Documented (developers.openai.com/codex, "Config and state locations",
"History persistence" and the config reference): state lives under
`CODEX_HOME`, `history.jsonl` holds session transcripts unless
`history.persistence = "none"`, and `sqlite_home` is the dir of the SQLite
state DB. The docs give no default for it, so jarx uses `CODEX_HOME`,
where the files are observed.

Observed, not documented:

- Rollouts at `sessions/YYYY/MM/DD/rollout-<ts>-<id>.jsonl`, older ones
  compressed as `.jsonl.zst`. Each line is `{timestamp, ordinal, type,
  payload}`. `session_meta` names the session (`session_id`, which a
  sub-agent shares with its parent, else `id`) and its cwd. `turn_context`
  has `approval_policy` (a value, or a `granular` object), the
  `approvals_reviewer` and `sandbox_policy.type`. Each is kept as a mode
  like `approval_policy=never`. A granular policy is kept as
  `approval_policy=granular`: its flags say which prompts are
  auto-rejected (config reference), so it doesn't hand approval to
  anything else.
- Codex replays a resumed session into a new rollout, so sessions merge by
  id across files. A `.zst` can't be read from an offset, but Codex
  compresses a session once it's done, so jarx reads it whole when it's
  new or changed. The decoder's window and output are capped.
- `state_N.sqlite` has a `threads` table with each thread's cwd, approval
  mode, sandbox and time. Those rows add sessions too.
  `memories_N.sqlite` has the raw memories Codex wrote, checked for leaks
  by row.

SQLite files are opened through `fsys.DBPath`, which checks them like a
read (inside the fake home, not a network path, not a credential, and
the `-wal`, `-shm` and `-journal` files next to them too). A missing table
or column is "unknown". A lock is `JARX-HISTORY-003` (info).

### Codex memories are instructions

Codex puts its local memories into context
(learn.chatgpt.com/docs/customization/memories), so jarx treats them like
any instruction file: the poison and secret rules run on them, a secret
in one is `JARX-SECRET-001` and shows as "sees" in the credential view,
and they're listed with what Codex loads. The files are everything in
`$CODEX_HOME/memories/` (v1) and `memories_v2/` (v2), since the desktop
app reads both during the migration and the docs don't say which file a
session reads. They load on demand, and only while `features.memories`
is on (off by default) and `memories.use_memories` isn't false.

### Observed formats

The docs don't cover most of this:

- the per-entry `permissionMode` in Claude transcripts (the docs call the
  format internal)
- the Codex `sessions/` folder and its `.zst` rollouts
- the Codex `*.sqlite` files
- per-session approval and sandbox values in Codex

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
- `JARX-POISON-014` (medium): annotations that lie. A tool marked
  `readOnlyHint` that's also marked `destructiveHint`, or whose name has a
  word that says it changes things (`delete_notes`, `pushFiles`). Codex
  doesn't ask before a tool marked read-only, even one also marked
  destructive.
- `JARX-POISON-015` (medium): tool shadowing, two servers the same agent
  loads in a project offering the same tool name.

On MCP text, the hits of one rule on one tool are one finding that lists
what matched, since a tool's text has no lines to tell them apart.

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

Rules on one server's definition live in `analyze/mcpconfig`. They run on
every server the agent would start, may start, or waits to approve, since
one waiting to be approved is the one a repository wants started.

- `JARX-MCP-001` (medium): an unpinned package runner (`npx`, `bunx`,
  `pnpm dlx`, `npm exec`, `uvx`, `pipx run`, `uv tool run`) with `@latest`,
  a range or no version.
- `JARX-MCP-002` (medium): a container image (`docker`, `podman` or
  `nerdctl run`) with no tag or `latest`.
- `JARX-MCP-003` (medium): a server started through a shell's `-c`
  (`sh -c`, `cmd /c`, `powershell -Command`).
- `JARX-MCP-004` (high): a server program in a temp or downloads dir.
- `JARX-MCP-005` (medium): an install from a git branch or default ref
  (`git+https://...#main`, `github:owner/repo`) instead of a commit, since
  the code can change under the same config.
- `JARX-MCP-006` (medium): a repository's server that runs a script from the
  repo (`node ./scripts/x.js`, `python tools/server.py`). Anyone who can push
  to the repo controls that server.
- `JARX-MCP-007` (medium): Codex `env_vars` forwarding a secret-looking var
  into a server.
- `JARX-MCP-008` (medium): a plain `http://` URL to a host that isn't
  loopback.
- `JARX-MCP-009` (info): `headersHelper` / `http_headers_helper`, which runs
  a command at connect.
- `JARX-MCP-010` (medium): broad filesystem args (a server given `/`, `~`,
  your home dir or a drive root).
- `JARX-MCP-011` (high) and `JARX-MCP-012` (medium): a server whose command
  is a `.bat` or `.cmd` file (or a bare name like `npx` that's one on
  Windows) with `cmd.exe` metacharacters in its args. `cmd.exe` reads them
  as syntax when the agent starts the server, so the config can run a
  command it never names. 011 when a repository's or plugin's config does
  it, 012 in your own. This is a finding of its own, apart from the "failed
  to start" status jarx gives the server.
- Tokens in a URL and secrets in headers are the secrets rules' job
  (`JARX-SECRET-002`).

Rules that depend on an agent's precedence live in its adapter:

- `JARX-CLAUDE-006` (high): a repository's `.mcp.json` server that takes the
  name of one of your user servers, so your permission rules for that name
  apply to the repository's server once it's approved. A local server wins
  over the project's, so it can't be replaced this way.
- `JARX-CLAUDE-007` (info): the same server name in two scopes with
  different endpoints.
- `JARX-CODEX-009` (high): a trusted repository's `[mcp_servers.<id>]` that
  redefines one of your servers while your config sends it a credential
  (`bearer_token_env_var`, `env_http_headers`, `http_headers`, `env`) the
  repository's doesn't set. If Codex merges the tables, your credential goes
  where the repository points the server.
- `JARX-CODEX-010` (medium): the same with no credential involved.

### Permissions and auto-approval

- `JARX-PERMS-001` (high): Claude's default mode is `bypassPermissions`.
- `JARX-PERMS-002` (high): Codex runs with no sandbox, through
  `sandbox_mode = "danger-full-access"` or
  `default_permissions = ":danger-full-access"`.
- `JARX-PERMS-003` (medium): Codex `approval_policy = "never"`.
- `JARX-PERMS-004` (high): a Claude allow for every command: `Bash`,
  `Bash(*)` (the docs say they're the same), or the PowerShell forms.
- `JARX-PERMS-005` (high): a grant that covers a credential file: a Claude
  `Read` or `Edit` allow, an `additionalDirectories` entry, a sandbox
  `allowRead` or `allowWrite` path, or a Codex profile `read` or `write`
  path. The credential paths are credmeta's, the same list the read guard
  uses.
- `JARX-PERMS-006` (medium): `enableAllProjectMcpServers` is on. Codex
  per-tool `approval_mode = approve` comes with phase 4.
- `JARX-PERMS-007` (info): Codex `approval_policy = "untrusted"` (retired,
  and the docs say it can stop Codex from starting) or `"on-failure"`
  (deprecated).
- `JARX-PERMS-008` (high): an allow that looks narrow but runs any code: an
  interpreter, shell or wrapper with open args (`Bash(python *)`,
  `Bash(sh -c *)`, `Bash(env *)`, `Bash(sudo *)`, `Bash(npx *)`), or a package
  manager open after its name (`Bash(npm *)` covers `npm exec`).
- `JARX-PERMS-009` (medium): an allow that runs code the repo defines, so
  whoever can push to the repo decides what runs: `Bash(npm run *)`,
  `Bash(make *)`, `Bash(pytest *)`, `Bash(cargo test *)`, `Bash(./scripts/*)`.
- `JARX-PERMS-010` (medium): an allow for a tool with a way to run any
  command, like `Bash(git *)` (`git -c` and aliases).
- Skill and command `allowed-tools` count as allows for 004, 005 and 008 to
  010. Only grants in effect count.
- `JARX-PERMS-011` (high): a deny or ask rule whose tool is misspelled, like
  `Raed(./.env)`. Claude has no such tool, so the rule applies to nothing
  and the protection it was meant to add is off. The same idea as a
  misspelled safety setting (`JARX-UNKNOWN-003`).
- `JARX-PERMS-012` (info): any other rule naming a tool the built-in tools
  catalog doesn't know: an allow typo, or a tool newer than the catalog.
  MCP tools (`mcp__...`), old names the docs still accept (`Task` for
  `Agent`) and removed tools aren't flagged.
- `JARX-PERMS-013` (high): a deny or ask rule that gives `Grep`, `Glob` or
  `Write` a path. The permissions docs say Claude accepts these but never
  matches them (it checks against `Read` and `Edit` rules), so the rule
  protects nothing.
- Codex `sandbox_mode` silently overriding permission profiles: high when a
  project file does it (a repository turning off your deny rules), medium
  when it's your own layers.
- A trusted project changing a Codex permission profile another layer
  defines.
- A `[sandbox_workspace_write]` table Codex ignores because permission
  profiles are in use: the permissions guide says to use profiles or the
  older sandbox settings, not both, and only `sandbox_mode` (or managed
  `allowed_permission_profiles` the other way) decides which. Info
  (`JARX-CODEX-007`), or medium (`JARX-CODEX-008`) when the table sets
  `exclude_slash_tmp` or `exclude_tmpdir_env_var`, which would have tightened
  the sandbox.
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

- `JARX-REACH-001` (medium): credentials an agent can read with its file
  tools or the shell without asking you, readable silently or past a
  bypassable deny. One finding per project and agent, naming the
  credentials.
- `JARX-REACH-002` (high): a deny for a credential that doesn't hold. For
  Claude, a `Read` deny or ask the shell can get around (`grep -r`, a
  script) because no sandbox backs it up. For Codex on native Windows, a
  profile deny the `unelevated` sandbox can ignore. On the rule's own
  file.
- **Drift:** when a tool description's hash changes, that tool goes through
  the poison rules again. It isn't just flagged as "changed". The poison
  rules run on every tool's current text each scan, so the changed one is
  checked again too.
  - `JARX-DRIFT-001` (medium): a tool, prompt or resource whose definition
    changed since the last scan.
  - `JARX-DRIFT-002` (info): a server listed in the last scan offering
    something new. A server seen for the first time isn't drift; the
    snapshot diff shows it as new.
- **Vulnerable agent version:** an install whose package name and version fall
  in an advisory's affected range (`JARX-VERSION-001` to `003`).

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

The catalog is stamped with the agent version it was built against: the
newest release on the day the docs were checked. If an installed agent is
newer than that, jarx shows a warning that the agent may have tools the
catalog doesn't know about. A version jarx can't find or read counts the
same as newer. jarx never fetches the catalog at runtime; a refresh means
checking the docs again and moving the stamp.

The catalog can only make a verdict worse, never better. While the agent is
newer than the catalog, or its version is unknown, jarx won't call a
credential "not reachable" outright: it says "not reachable by the tools
jarx knows" and names the catalog's version in the why trail. A rule naming
a tool the catalog lacks is the other sign of a newer agent (or a typo),
and works without any version (`JARX-PERMS-011`, `JARX-PERMS-012`). An agent
older than the catalog may lack some listed tools, which only overstates
reach.

Where the docs don't say whether a tool asks first, the catalog says
"unknown" instead of guessing. Codex's built-in tools have no permission
rules of their own: `approval_policy` and the sandbox decide.

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
- Claude's sandbox: `sandbox.enabled` and its switches as options, and the
  `sandbox.filesystem` path lists as rules. They're in effect only while the
  sandbox runs, which the docs say isn't on native Windows.
- An allow that a deny or ask rule covers is not in effect, since Claude
  checks deny, then ask, then allow. jarx counts a rule for the whole tool
  or the same rule; it doesn't work out how two different patterns overlap.

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

What jarx reads for it, from the docs (Claude's env vars and settings
references; Codex's config reference and advanced config):

- Claude's env vars come from a fixed list in the catalog: the base URLs and
  `CLAUDE_CODE_USE_*` switches, `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`, and
  the TLS vars the docs name (`NODE_EXTRA_CA_CERTS`, `CLAUDE_CODE_CERT_STORE`,
  the client cert and key paths). Only those keep their values, from the env
  or a settings `env` block, with any password in a URL masked. For a
  credential var (`ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`,
  `CLAUDE_CODE_OAUTH_TOKEN` and the like) jarx only notes that it's set.
  Neither agent's docs name a setting that turns TLS checks off, so jarx
  doesn't look for one.
- Codex ignores `openai_base_url`, `chatgpt_base_url`, `model_provider`,
  `model_providers` (and `notify`, `profile`, `profiles`, `otel`,
  `experimental_realtime_ws_base_url`, `apps_mcp_product_sku`) in a
  project's `.codex/config.toml`, and warns at startup. jarx marks those not
  in effect, so a repository can't redirect Codex's endpoint.

Findings:

- `JARX-EGRESS-001` (high): a repository's `.claude/settings.json` that sets
  the model endpoint or provider in its env block, so your prompts, code and
  key go where the repository chose.
- `JARX-EGRESS-002` (medium): a repository that sets a proxy for the agent
  (Claude's `HTTPS_PROXY` or `HTTP_PROXY` in a project env block, Codex's
  `features.network_proxy` URLs). `NO_PROXY` doesn't count.
- `JARX-EGRESS-003` (info): a repository's Codex config that sets the
  endpoint or provider. Codex ignores it, so it's a note, not a risk.

The scan shows a `talks to:` line per project (`claude
llm-gateway.example.com - 1 MCP host - proxy set - codex default API - web
search cached`), and `--all` lists each agent's settings in full with where
each was set.

## Optional LLM review

Off unless the user sets it up. Without it, jarx is rules only.

Any OpenAI-compatible endpoint works. jarx needs three things: a base URL, a
model and the name of an env var that holds the key. jarx never stores the
key, not in its config and not in a keychain. It reads the var when a review
runs and only sends it to the base URL. It never picks up a key from the env
on its own, only from the var you named.

Set the key only in the terminal you run jarx from. A key in your shell
profile is in every agent's env too, so the agents can read it. To set it
without it landing in shell history:

- PowerShell: `$env:JARX_LLM_KEY = [Net.NetworkCredential]::new('', (Read-Host -AsSecureString 'key')).Password`
- bash and zsh: `read -rs JARX_LLM_KEY && export JARX_LLM_KEY`

`jarx setup llm` asks one question at a time: the base URL, then the model,
then the env var name (`JARX_LLM_KEY` by default). Enter keeps the default,
and a bad answer gets the same question again with the reason:

- The base URL has to be `https://`, or `http://` to a loopback address. It
  can't hold a user, a password or a query string, and it can't be a cloud
  metadata address. A URL that looks like it holds a secret is refused, so
  a key can't end up in the config by accident. The model name and the var
  name get the same secret check.
- Right after the var name, jarx says whether that var is set in this
  terminal (never its value), with the commands above when it isn't.
- Then it shows a short summary and asks whether to save. Ctrl+C or the end
  of input before that saves nothing and says "cancelled, nothing saved".
- After saving it asks whether to test the connection (default no), since
  that's a network call. The test sends one short request with fixed text
  and no scan content. It's skipped when the var isn't set.

When input or output isn't a terminal, `jarx setup llm` asks nothing and
says how to use the one-line version for scripts: `jarx setup llm --url
<url> --model <model> --key-env <name>`. That version needs all three, runs
the same checks, saves and never tests. `jarx setup llm off` clears the LLM
settings and leaves the env var alone. `jarx setup` shows the current ones.

The review runs only on `jarx scan --llm` or the dashboard button. Before
sending anything, jarx shows how many artifacts it will send, roughly how many
tokens, and to which host, and asks yes or no (default no). When input or
output isn't a terminal, `--llm` refuses before scanning and says why. It
also refuses when the LLM isn't set up or the env var isn't set.

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
- A snapshot keeps each thing a scan found with its state: projects,
  instruction files, skills, hooks, permission rules and settings, config
  files, findings and unknown keys. Texts are kept only as a hash of their
  masked form, so jarx never keeps copies of your instruction and memory
  files, and a changed secret shows as "content changed" without the value.
- The diff lists what's new, gone, or changed (now in effect or not, content
  changed, value changed), scan-wide items first, then by project. The first
  scan says there's no earlier snapshot. A broken snapshot, or one from a
  newer jarx, means no diff and a note, never a failed scan.
- To compare against an older snapshot, use the snapshot picker in the
  dashboard.
- Named baselines are for later.

## CLI

The CLI stays small: three commands and a version flag.

| Command | What it does |
|---|---|
| `jarx scan [path...]` | full scan, prints what it checked, then the findings grouped by project, worst first, plus what changed since the last scan. Extra paths are scanned for this run only. |
| `jarx ui` | start the dashboard |
| `jarx setup` | show jarx's own settings: extra repo paths, and whether the LLM is set up |
| `jarx setup repo add\|rm <path>` | add or remove an extra project path |
| `jarx setup llm` | set the base URL, model and key env var name, one question at a time |
| `jarx setup llm --url <url> --model <model> --key-env <name>` | the same in one line, for scripts |
| `jarx setup llm off` | clear the LLM settings |
| `jarx --version` | print the banner, version and advisory data date |

Flags:

| Flag | On | What it does |
|---|---|---|
| `--home <dir>` | `scan`, `ui`, `setup` | treat `<dir>` as the home dir instead of the real one (see [Demo home](#demo-home)) |
| `--all` | `scan` | show every finding with its full reason and fix, what jarx resolved about the machine, and the full inventory |
| `--no-probe` | `scan` | skip MCP probing |
| `--no-history` | `scan` | skip session history |
| `--llm` | `scan` | run the LLM review after showing the preview |

### Terminal output

A scan should be readable at a glance in any terminal: PowerShell, Windows
PowerShell 5.1, cmd, Windows Terminal, macOS Terminal, iTerm2 and Linux
terminals.

- It shows what jarx checked first, then what it found. Findings are grouped
  by project, worst first, and user-level problems show once on their own.
- Long lists stop at 10 findings per project, but every high or critical
  one shows. The rest are counted. `--all` shows everything.
- Lines fit the terminal's width and never wrap. Paths are short: from `~`
  or the project.
- Color is the basic 16 only and never the only way something is said. It
  turns off when output is piped, with `NO_COLOR`, and with `TERM=dumb`.
  Piped output is plain ASCII.
- Every run starts with a banner and the version next to it.

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

Probing under `--home` never contacts a remote server and never starts a
program from the fake PATH; those servers show as "not started" and say
why. The one server it starts is the demo's fake one: a stdio server whose
command is `jarx-fakemcp <script>`, which jarx serves itself from a script
inside the fake home. On the real machine `jarx-fakemcp` is just a command
name like any other.

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
  - set the LLM base URL, model and key env var name. The page never takes
    the key itself, and only shows whether the var is set.
  - rescan
- A pasted repo still only probes servers the agent would start.
- Never writes agent config.

## Network calls

This is the full list. Anything not here is a bug.

| When | What | To where | Turned off by |
|---|---|---|---|
| `jarx scan` with probing (default) | MCP `server/discover` or `initialize` and list calls to remote servers that would connect anyway, with their configured static creds if any | the server's configured `https://` URL | `--no-probe` |
| `jarx scan` with probing (default) | jarx starts stdio servers. **The servers themselves** may use the network (for example `npx` downloading a package), just like when the agent starts them | whatever the server does | `--no-probe` |
| `jarx scan --llm` or dashboard button | LLM review requests, redacted | the base URL the user set up | don't pass `--llm` |
| `jarx setup llm`, after you answer yes to the test | one short chat request with fixed text and no scan content, with the key | the base URL just saved | answer no (the default) |
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
  Reading it never creates the state dir.
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
release can't silently add a setting jarx ignores. Unknown keys are findings,
never errors.

- Claude's keys are the settings index, plus `$schema` (the settings page
  shows it as the line that points editors at the schema) and the two
  documented marketplace aliases. Codex's keys are every row in the config
  reference's `config.toml` and `requirements.toml` tables, with the aliases
  the rows name. `[hooks]` isn't checked inside: the reference sends its
  fields to the Hooks guide.
- A key one or two edits from a known key at the same level (one for keys
  under five chars, a swap counts as one, case doesn't count) is a likely
  typo, and the report says "did you mean".
- `JARX-UNKNOWN-001` (info): a key the docs don't list. It may be newer than
  jarx's table, or deprecated, and the report says which when the docs do.
- `JARX-UNKNOWN-002` (medium): a likely typo, so the setting it was meant to
  be isn't set by that file.
- `JARX-UNKNOWN-003` (high): a likely typo of a key that protects you, so
  someone thinks they're protected when they're not. For Claude that's
  `permissions.*`, `sandbox.*`, the mode locks and the managed-only switches;
  for Codex the sandbox, approval, permission profile and shell environment
  keys, and every `requirements.toml` key. A typo of a key that loosens
  things, like `enableAllProjectMcpServers`, leaves you safer than you
  think, so it's 002.
- `JARX-CLAUDE-005` (info): a key alias in the same file as its canonical
  key. The settings reference says Claude then ignores the alias.

### Fixtures per agent version

Test fixtures are fake config trees organized by agent version (for example
`testdata/claude/<version>/`, `testdata/codex/<version>/`), including the
observed history formats. When a new agent version changes a format, it gets
a new fixture dir and the old ones keep passing.

## Dependencies

Approved for v1:

- `github.com/BurntSushi/toml`: Codex config
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

- **Credentials the docs don't place.** GnuPG's Windows default dir and ssh
  keys that `~/.ssh/config` points at outside `~/.ssh` aren't found.

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
- **Codex hook fields.** The config reference sends `[hooks]` fields to the
  Hooks guide, so jarx doesn't check keys inside `[hooks]` for typos.
- **Key tables lag new releases.** A key newer than jarx's tables shows as
  unknown until the table is updated. Its finding says so.
- **Codex's command allowlist.** Codex's execution-policy rules files can
  pre-approve commands. jarx doesn't read them yet.
- **Commands beyond the table.** `JARX-PERMS-008` to 010 come from an
  embedded table of interpreters, runners and tools. A program that isn't
  in it, or a less common way to run code (like GNU `sed`'s `e` command),
  isn't flagged.
- **Claude mode locks the docs leave open.** jarx doesn't count a lock from
  an untrusted project's files, since the docs don't say whether Claude reads
  it before trust and counting one it ignores would hide a live bypass. And
  when bypass is locked, the docs don't say which mode a session starts in,
  so jarx shows no default mode in effect.
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
- **Probed servers that leave their process group.** On macOS and Linux a
  stdio server runs in its own process group, and a kill goes to the
  group. A program it starts that calls `setsid` leaves the group and
  isn't killed. On Windows the job object holds the whole tree.
- **`.cmd` servers with shell characters in their args.** jarx won't pass
  an argument with a `cmd.exe` metacharacter (`&`, `|`, `%`, quotes and the
  like) to a `.bat` or `.cmd` file, since `cmd.exe` could run it as a
  command. Such a server shows as "failed to start" with that reason.
- **Static analysis only.** Verdicts come from settings and docs, not from
  testing the agent.

## Later

- CI gate: exit codes, JSON and SARIF export.
- Named baselines (`jarx baseline`).
- Typosquat and lookalike detection.
- Behavior evidence from history (file reads, network calls by tools).
- Cross-artifact LLM review.
- The LLM key in the OS keychain, under jarx's own entry, as an option next
  to the env var. v1 never stores the key.
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
