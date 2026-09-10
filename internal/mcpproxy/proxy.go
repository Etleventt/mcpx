package mcpproxy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"mcpx/internal/config"
	"mcpx/internal/logging"
)

// Proxy manages upstream MCP stdio processes (minimal Phase: list + call via raw is complex).
// For M5 we expose configured servers and run a simple "tools/list via npx" is heavy.
// Practical approach: list from config; call spawns one-shot or reuse client from mcp-go.

// Manager is an immutable request-local view of merged MCP server configs.
type Manager struct {
	servers map[string]config.MCPServer
	enabled bool
}

// NewManager from merged MCP file.
func NewManager(enabled bool, file config.MCPFile) *Manager {
	m := &Manager{servers: map[string]config.MCPServer{}, enabled: enabled}
	for name, s := range file.MCPServers {
		m.servers[name] = s
	}
	return m
}

// List returns stable, secret-free machine-readable server descriptors.
func (m *Manager) List() []map[string]any {
	if !m.enabled {
		return []map[string]any{}
	}
	names := make([]string, 0, len(m.servers))
	for name := range m.servers {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]map[string]any, 0, len(names))
	for _, name := range names {
		srv := m.servers[name]
		remoteType, typeErr := remoteTransportType(srv)
		typeName := remoteType
		if typeName == "" {
			typeName = "stdio"
		}
		item := map[string]any{
			"name": name, "type": typeName, "state": "configured",
			"source": "merged_config",
			"invocation": map[string]any{
				"tool":      "mcp_call",
				"arguments": map[string]any{"server": name, "tool": "<upstream_tool>", "arguments": map[string]any{}},
			},
			"tool_discovery": map[string]any{
				"tool": "mcp_list", "arguments": map[string]any{"server": name, "include_tools": true},
			},
		}
		if remoteType != "" {
			item["endpoint"] = DescribeTarget(srv)
			item["authentication"] = AuthenticationDescriptor(srv)
		}
		if typeErr != nil {
			item["state"] = "invalid_config"
			item["config_error"] = typeErr.Error()
		}
		out = append(out, item)
	}
	return out
}

// ExpandEnv replaces ${VAR} in env map values.
func ExpandEnv(env map[string]string) []string {
	var out []string
	for k, v := range env {
		out = append(out, k+"="+os.ExpandEnv(v))
	}
	return out
}

// PingCommand validates that the configured upstream target is invokable. It
// intentionally does not perform a network handshake; tool discovery does that.
func (m *Manager) PingCommand(ctx context.Context, name string) error {
	_ = ctx
	srv, ok := m.servers[name]
	if !ok {
		return fmt.Errorf("server %q not configured", name)
	}
	remoteType, err := remoteTransportType(srv)
	if err != nil {
		return err
	}
	if remoteType != "" {
		_, err = buildRemoteRequestConfig(srv)
		return err
	}
	if srv.Command == "" {
		return fmt.Errorf("empty command")
	}
	// best-effort: resolve look path
	_, err = exec.LookPath(srv.Command)
	if err != nil {
		// npx may still work via path later
		logging.Debug("mcp lookpath", "server", name, "err", err)
	}
	return nil
}

// Call is a placeholder that returns structured error until full MCP client wiring.
// Real call uses mcp-go client stdio — implemented in CallTool.
func (m *Manager) Has(name string) bool {
	if !m.enabled {
		return false
	}
	_, ok := m.servers[name]
	return ok
}

// ServerConfig returns config for name.
func (m *Manager) ServerConfig(name string) (config.MCPServer, bool) {
	if !m.enabled {
		return config.MCPServer{}, false
	}
	srv, ok := m.servers[name]
	return srv, ok
}

// DescribeCommand returns command line for logging (no secrets).
func DescribeCommand(s config.MCPServer) string {
	return strings.TrimSpace(s.Command + " " + strings.Join(s.Args, " "))
}
