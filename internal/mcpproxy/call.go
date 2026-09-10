package mcpproxy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcpx/internal/config"
	"mcpx/internal/logging"
	buildversion "mcpx/internal/version"
)

// CallTool connects to one configured upstream MCP server, calls a tool, and
// closes the short-lived client session.
func CallTool(ctx context.Context, srv config.MCPServer, toolName string, arguments map[string]any) (any, error) {
	session, err := connect(ctx, srv, 60*time.Second)
	if err != nil {
		return nil, err
	}
	defer session.Close()

	if arguments == nil {
		arguments = map[string]any{}
	}
	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      toolName,
		Arguments: arguments,
	})
	if err != nil {
		return nil, redactMCPError(srv, err)
	}
	logging.Debug("mcp call ok", "tool", toolName, "target", DescribeTarget(srv))
	return res, nil
}

// ListTools connects to one upstream server and returns its tools/list items.
func ListTools(ctx context.Context, srv config.MCPServer) ([]*mcp.Tool, error) {
	session, err := connect(ctx, srv, 30*time.Second)
	if err != nil {
		return nil, err
	}
	defer session.Close()

	listed, err := session.ListTools(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("tools/list: %w", redactMCPError(srv, err))
	}
	if listed == nil {
		return nil, nil
	}
	return listed.Tools, nil
}

func connect(ctx context.Context, srv config.MCPServer, timeout time.Duration) (*mcp.ClientSession, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	// cancel is not deferred: the short-lived session owns the connection and
	// its caller closes the session immediately after list/call completes.
	_ = cancel
	client := mcp.NewClient(&mcp.Implementation{Name: "mcpx", Version: buildversion.Current}, nil)

	remoteType, err := remoteTransportType(srv)
	if err != nil {
		return nil, err
	}
	if remoteType != "" {
		session, err := connectRemote(ctx, client, srv, remoteType)
		if err != nil {
			return nil, fmt.Errorf("connect upstream mcp: %w", redactMCPError(srv, err))
		}
		return session, nil
	}
	if srv.Command == "" {
		return nil, fmt.Errorf("empty command")
	}
	cmd := exec.CommandContext(ctx, srv.Command, srv.Args...)
	cmd.Env = append(os.Environ(), ExpandEnv(srv.Env)...)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		return nil, fmt.Errorf("connect upstream mcp: %w", err)
	}
	return session, nil
}
