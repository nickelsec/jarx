package mcpconfig

import "github.com/nickelsec/jarx/internal/finding"

// UnpinnedRunner is a package runner (npx, uvx and the like) with no exact
// version, so the code it runs can change under the same config.
func UnpinnedRunner() finding.Rule {
	return finding.Rule{
		ID: "JARX-MCP-001", Severity: finding.Medium, Title: "An MCP server runs an unpinned package",
		Detail: "the server is started by a package runner with no exact version, so a new release of the package runs next time with no change to the config",
		Fix:    "pin an exact version, like name@1.2.3 or name==1.2.3",
	}
}

// UnpinnedImage is a container image with no tag, or latest.
func UnpinnedImage() finding.Rule {
	return finding.Rule{
		ID: "JARX-MCP-002", Severity: finding.Medium, Title: "An MCP server runs an image on latest",
		Detail: "the server runs a container image with no tag or the latest tag, so whatever gets pushed next runs",
		Fix:    "pin a version tag, or better a digest (image@sha256:...)",
	}
}

// ShellCommand is a server started through a shell's -c, so its command is
// a string the shell runs, with pipes and all.
func ShellCommand() finding.Rule {
	return finding.Rule{
		ID: "JARX-MCP-003", Severity: finding.Medium, Title: "An MCP server is started through a shell",
		Detail: "the server's command is a shell running a string (sh -c, cmd /c, powershell -Command), which can chain or download anything",
		Fix:    "start the server's program directly with its arguments",
	}
}

// TempBinary is a server program in a temp or downloads dir, where anything
// can drop a file.
func TempBinary() finding.Rule {
	return finding.Rule{
		ID: "JARX-MCP-004", Severity: finding.High, Title: "An MCP server runs from a temp dir",
		Detail: "the server's program is in a temp or downloads dir, where other programs and downloads can replace it",
		Fix:    "install the server somewhere only you can write, like a package manager's dir",
	}
}

// GitBranch is a server installed from a git ref that isn't a commit.
func GitBranch() finding.Rule {
	return finding.Rule{
		ID: "JARX-MCP-005", Severity: finding.Medium, Title: "An MCP server installs from a git branch",
		Detail: "the server installs from a git repository at a branch or default ref, so a push to it changes what runs",
		Fix:    "pin the full commit hash (#<sha> or @<sha>), or install a released version",
	}
}

// RepoScript is a repository's server that runs a script from the repo.
func RepoScript() finding.Rule {
	return finding.Rule{
		ID: "JARX-MCP-006", Severity: finding.Medium, Title: "A repo MCP server runs the repo's code",
		Detail: "a server in the repository's config runs a script that lives in the repository, so anyone who can push to it decides what the server does",
		Fix:    "review the script, or run a released package instead",
	}
}

// ForwardsSecret is a Codex server that forwards a secret-looking env var.
func ForwardsSecret() finding.Rule {
	return finding.Rule{
		ID: "JARX-MCP-007", Severity: finding.Medium, Title: "An MCP server gets a secret from your env",
		Detail: "env_vars forwards a variable whose name says it holds a secret, so the server can use the credential",
		Fix:    "forward only what the server needs, and give it its own scoped credential",
	}
}

// PlainHTTP is a remote server on plain http to a host that isn't loopback.
func PlainHTTP() finding.Rule {
	return finding.Rule{
		ID: "JARX-MCP-008", Severity: finding.Medium, Title: "An MCP server uses plain http",
		Detail: "a remote server's URL is plain http:// to a host that isn't loopback, so requests and any token go over the network unencrypted",
		Fix:    "use the server's https:// URL",
	}
}

// HeadersHelper is a remote server whose headers come from a command run at
// connect.
func HeadersHelper() finding.Rule {
	return finding.Rule{
		ID: "JARX-MCP-009", Severity: finding.Info, Title: "An MCP server runs a headers helper",
		Detail: "a command runs every time the agent connects, to build the server's headers.",
		Fix:    "check what the helper runs, since it runs with your rights",
	}
}

// BroadFilesystem is a server given the root or your home dir.
func BroadFilesystem() finding.Rule {
	return finding.Rule{
		ID: "JARX-MCP-010", Severity: finding.Medium, Title: "An MCP server gets your whole disk",
		Detail: "a server is given the filesystem root or your home dir as an argument, which covers your keys and every other project",
		Fix:    "give it only the dirs it needs, like the project",
	}
}

// RepoBatchArgs is a repository's .bat or .cmd server with cmd.exe syntax
// in its args.
func RepoBatchArgs() finding.Rule {
	return finding.Rule{
		ID: "JARX-MCP-011", Severity: finding.High, Title: "A repo .cmd server's args run commands",
		Detail: "the server's command is a .bat or .cmd file, which runs through cmd.exe, and a repository's config gives it arguments with cmd.exe metacharacters (& | < > ^ % ! quotes), so starting it can run a command the config never names",
		Fix:    "remove the metacharacters, or run the server's program directly",
	}
}

// OwnBatchArgs is the same in your own config.
func OwnBatchArgs() finding.Rule {
	return finding.Rule{
		ID: "JARX-MCP-012", Severity: finding.Medium, Title: "A .cmd MCP server's args have cmd syntax",
		Detail: "the server's command is a .bat or .cmd file, which runs through cmd.exe, and its arguments have cmd.exe metacharacters, so starting it can run something else",
		Fix:    "remove the metacharacters, or run the server's program directly",
	}
}

// Rules returns the analyzer's rules.
func Rules() []finding.Rule {
	return []finding.Rule{
		UnpinnedRunner(), UnpinnedImage(), ShellCommand(), TempBinary(), GitBranch(), RepoScript(),
		ForwardsSecret(), PlainHTTP(), HeadersHelper(), BroadFilesystem(), RepoBatchArgs(), OwnBatchArgs(),
	}
}
