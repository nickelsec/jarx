# jarx

jarx maps what Claude Code and Codex can see and reach on a developer's
machine: instruction files, MCP servers, skills, hooks, permissions and
credentials. Single Go binary with a CLI and a local dashboard.

## Hard rules
- jarx never opens credential stores. It reports that they exist and where.
- Any secret jarx finds inside a config file is masked in memory and never
  reaches the LLM, logs, test output or the dashboard.
- jarx lists MCP servers and tools but never calls them.
- The dashboard binds to `127.0.0.1` only.
- Tests use fake fixtures only, never real configs from this machine.
- These security behaviors get tests like any other feature.
- Write our own detection rules. Don't copy other scanners.
- Take config paths from the official docs. Never guess.
- Support Windows, macOS and Linux config paths. No Windows-only path logic.

## How we work
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
