package server

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"mcpx/internal/auth"
	"mcpx/internal/config"
	"mcpx/internal/envelope"
	"mcpx/internal/mcpresult"
	"mcpx/internal/remotesession"
)

func TestProjectMCPRequiresConfirmationBeforeExecutableDiscovery(t *testing.T) {
	runtime := newWorkspaceRuntime(t, "demo")
	registered, ok := runtime.reg.Get("demo")
	if !ok {
		t.Fatal("demo workspace was not registered")
	}
	projectConfigDir := filepath.Join(registered.Path, ".mcpx")
	if err := os.MkdirAll(projectConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(registered.Path, "project-mcp-started")
	projectMCP := config.MCPFile{MCPServers: map[string]config.MCPServer{
		"untrusted-project-server": {Type: "stdio", Command: "/bin/sh", Args: []string{"-c", "printf started > " + marker + "; exit 1"}},
	}}
	raw, err := json.Marshal(projectMCP)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.ProjectMCPPath(registered.Path), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	principal, err := runtime.principalFromContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	created, err := runtime.remote.Create(context.Background(), principal, remotesession.CreateInput{WorkspaceName: "demo", WorkspacePath: registered.Path})
	if err != nil {
		t.Fatal(err)
	}
	baseArguments := map[string]any{"workspace": "demo", "remote_session_id": created.Session.ID, "kind": "mcp", "view": "list", "include_tools": false, "client_request_id": "project-mcp-list"}
	listed, err := runtime.toolExtensionDiscover(context.Background(), mcpresult.Request(baseArguments))
	if err != nil {
		t.Fatal(err)
	}
	listedResponse := decodeToolResult(t, listed)
	if !statusOK(listedResponse) {
		t.Fatalf("configuration-only list response=%+v", listedResponse)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("configuration-only list executed the project MCP: %v", err)
	}
	discoverArguments := cloneArguments(baseArguments)
	discoverArguments["include_tools"] = true
	discoverArguments["client_request_id"] = "project-mcp-discover"
	pending, err := runtime.toolExtensionDiscover(context.Background(), mcpresult.Request(discoverArguments))
	if err != nil {
		t.Fatal(err)
	}
	pendingResponse := decodeToolResult(t, pending)
	if pendingResponse["public_status"] != "waiting_confirmation" {
		t.Fatalf("first executable discovery response=%+v", pendingResponse)
	}
	pendingData, _ := pendingResponse["data"].(map[string]any)
	confirmationToken, _ := pendingData["confirmation_token"].(string)
	if confirmationToken == "" {
		t.Fatalf("confirmation token missing: %+v", pendingResponse)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unconfirmed project MCP was executed: %v", err)
	}
	confirmedArguments := cloneArguments(discoverArguments)
	confirmedArguments["confirmation_token"] = confirmationToken
	confirmed, err := runtime.toolExtensionDiscover(auth.ContextWithAuthorization(context.Background(), ""), mcpresult.Request(confirmedArguments))
	if err != nil {
		t.Fatal(err)
	}
	confirmedResponse := decodeToolResult(t, confirmed)
	if !statusOK(confirmedResponse) {
		t.Fatalf("confirmed discovery response=%+v", confirmedResponse)
	}
	if rawMarker, err := os.ReadFile(marker); err != nil || string(rawMarker) != "started" {
		t.Fatalf("confirmed project MCP marker=%q err=%v", rawMarker, err)
	}
}

func TestProjectMCPTrustedSessionSkipsConfirmation(t *testing.T) {
	runtime := newWorkspaceRuntime(t, "demo")
	registered, _ := runtime.reg.Get("demo")
	if err := os.MkdirAll(filepath.Join(registered.Path, ".mcpx"), 0o755); err != nil {
		t.Fatal(err)
	}
	projectMCP := config.MCPFile{MCPServers: map[string]config.MCPServer{"safe": {Type: "stdio", Command: "/bin/false"}}}
	raw, _ := json.Marshal(projectMCP)
	if err := os.WriteFile(config.ProjectMCPPath(registered.Path), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	principal, _ := runtime.principalFromContext(context.Background())
	created, err := runtime.remote.Create(context.Background(), principal, remotesession.CreateInput{WorkspaceName: "demo", WorkspacePath: registered.Path, ApprovalMode: remotesession.ApprovalModeTrusted})
	if err != nil {
		t.Fatal(err)
	}
	envReq := envelope.Request{RequestID: "req_trusted_project_mcp", RemoteSessionID: created.Session.ID, Workspace: "demo", Payload: map[string]any{}}
	result, err := runtime.requireProjectMCPTrust(context.Background(), envReq, principal, created.Session.ID, "demo", registered.Path)
	if err != nil || result != nil {
		t.Fatalf("trusted session should auto-approve project MCP confirmation: result=%v err=%v", result, err)
	}
}
