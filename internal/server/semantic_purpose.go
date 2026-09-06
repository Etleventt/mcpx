package server

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"mcpx/internal/envelope"
	"mcpx/internal/observation"
)

// inferSemanticPurpose keeps audit/observation context without making the model
// restate natural-language intent on every tool call. Explicit purpose from an
// older client is still accepted, sanitized, and bounded for compatibility.
func inferSemanticPurpose(tool string, req envelope.Request) string {
	if explicit := boundSemanticPurpose(req.Intent); explicit != "" {
		return explicit
	}
	tool = strings.TrimSpace(tool)
	payload := req.Payload
	text := func(key string) string {
		value, _ := payload[key].(string)
		return strings.TrimSpace(value)
	}
	action, view := text("action"), text("view")
	var purpose string
	switch tool {
	case "command_run", "command_execute":
		if task := text("task"); task != "" {
			purpose = "run task " + task
		} else {
			purpose = "run command"
		}
	case "change", "change_prepare", "change_execute":
		if summary := text("summary"); summary != "" {
			purpose = "change: " + summary
		} else if action != "" {
			purpose = "change " + action
		} else {
			purpose = "change workspace"
		}
	case "task", "task_manage":
		purpose = "task " + firstNonEmpty(action, "manage")
	case "plan", "plan_manage":
		purpose = "plan " + firstNonEmpty(action, "manage")
	case "operation_batch":
		count := 0
		if items, ok := payload["operations"].([]any); ok {
			count = len(items)
		}
		purpose = fmt.Sprintf("run batch (%d operations)", count)
	case "skill_call", "skill_execute":
		purpose = "call skill " + firstNonEmpty(text("name"), "extension")
	case "mcp_call", "mcp_execute":
		serverName, toolName := text("server"), text("tool")
		purpose = "call MCP " + strings.Trim(strings.TrimSpace(serverName+"/"+toolName), "/")
	case "artifact", "artifact_register":
		purpose = "register artifact"
	case "environment":
		purpose = "environment " + firstNonEmpty(action, "snapshot")
	case "screenshot_capture":
		purpose = "capture screenshot"
	case "secret_provide", "secrets_provide":
		purpose = "provide secret"
	default:
		if tool == "" {
			tool = "tool"
		}
		if action != "" {
			purpose = tool + " " + action
		} else if view != "" {
			purpose = tool + " " + view
		} else {
			purpose = tool
		}
	}
	purpose = boundSemanticPurpose(purpose)
	if purpose == "" {
		return "tool operation"
	}
	return purpose
}

func boundSemanticPurpose(value string) string {
	value = observation.SanitizeIntent(value)
	const maxBytes = 512
	for len(value) > maxBytes {
		_, size := utf8.DecodeLastRuneInString(value)
		if size <= 0 {
			return value[:maxBytes]
		}
		value = value[:len(value)-size]
	}
	return value
}
