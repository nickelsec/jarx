package claude

import (
	"strings"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/catalog"
	"github.com/nickelsec/jarx/internal/model"
)

// ruleTool is the tool a permission rule names: what comes before its
// parens, or the whole rule.
func ruleTool(rule string) string {
	name, _, _ := strings.Cut(rule, "(")
	return strings.TrimSpace(name)
}

// knownTool says whether Claude has a tool by this name: a built-in one
// in the catalog (old names and removed tools too, which aren't typos), or
// an MCP tool, which probe lists.
func knownTool(name string) bool {
	if strings.HasPrefix(name, "mcp__") {
		return true
	}
	_, ok := catalog.Tool(model.AgentClaude, name)
	return ok
}

// nearTool is the built-in tool an unknown name is most likely a typo of,
// or "".
func nearTool(name string) string {
	return agent.NearKey(name, catalog.ToolNames(model.AgentClaude))
}
