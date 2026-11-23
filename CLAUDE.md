# jarx

jarx maps what Claude Code and Codex can see and reach on a developer's
machine: instruction files, MCP servers, skills, hooks, permissions and
credentials. Single Go binary with a CLI and a local dashboard.

## Hard rules
- jarx never reads credential values. `.env` files are opened only to get key
  names. Ambient CLI creds (aws, gh, gcloud, ssh, etc) get existence plus safe
  metadata like profile names or whether an ssh key has a passphrase. The
  agents' own login files get existence only. jarx never reads other apps'
  OS keychain entries. It may store and read its own LLM key there.
- Any secret jarx finds inside a config file is masked in memory and never
  reaches the LLM, logs, test output or the dashboard.
- jarx lists MCP servers and tools but never calls them.
- The dashboard binds to `127.0.0.1` only.
- Tests use fake fixtures only, never real configs from this machine.
- These security behaviors get tests like any other feature.
- Write our own detection rules. Don't copy other scanners.
- Take config paths from the official docs. Never guess. History and state
  formats (session transcripts, Codex sqlite and zstd files) may come from
  observed structure, labeled "observed, not documented" in code and UI, and
  must degrade to "unknown" instead of erroring.
- Support Windows, macOS and Linux config paths. No Windows-only path logic.

## How we work
- Read docs/prd.md and docs/design.md before starting any feature.
- Build in the phases from docs/design.md. One branch and one PR per phase,
  opened as a draft early so the windows and mac checks run on every push.
  One commit per item in docs/progress.md.
- Tick the item in docs/progress.md in the same commit as the work. A commit
  can't hold its own hash, so the next commit adds it next to the tick.
- Before starting phase 7 (the dashboard), stop and ask me about the UI. I
  want to give input on how it looks before any `ui` code gets written.
- All terminal output, in every phase, follows the Terminal output section
  in docs/design.md and builds on it. New phases add to the same blocks and
  the same tree format instead of inventing new ones. If something fits no
  block, ask me first, then add it to that section.
- Keep the folder layout from the package table in docs/design.md, so things
  are easy to find. Only add a new folder when nothing existing fits. When you
  do, say why in chat and in the PR, and add it to that table.
- Every feature and bug fix: use the test-driven-development skill. Never
  edit a test just to make it pass.
- Before saying anything is done: use the verification-before-completion
  skill and show the command output.
- Tests: `go test ./...`. The skills show npm examples; use the Go equivalent.
- Run `gofmt -w` on changed Go files before saying anything is done.
- Ask before adding a dependency.
- Dev machine is native Windows with no sandbox. PowerShell is the main shell.

## Research
- Tavily to search, Firecrawl to read a specific page in full.
- Official docs (code.claude.com, developers.openai.com/codex) over blogs.

## Git
- Repo `nickelsec/jarx`, module `github.com/nickelsec/jarx`.
- Branches: `feat/`, `fix/` or `chore/` plus a short name.
- Commit messages: short, lowercase, plain.
- PR title under 60 characters. Body: What (1 to 3 bullets), Why (one line),
  How tested (the commands run).
- Ask me before every commit, push or PR.

## Writing
- Casual, plain words. No em dashes.
- Run the humanizer skill on prose docs (README, PRD, docs/), not on chat
  replies or code comments.
