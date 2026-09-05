package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcpx/internal/approval"
	"mcpx/internal/auth"
	"mcpx/internal/config"
	"mcpx/internal/envelope"
	"mcpx/internal/remotesession"
)

type projectMCPTrustKey struct {
	RemoteSessionID string
	PrincipalID     string
	ConfigDigest    string
}

type projectMCPTrustStore struct {
	mu      sync.RWMutex
	trusted map[projectMCPTrustKey]struct{}
}

func (s *projectMCPTrustStore) has(key projectMCPTrustKey) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.trusted[key]
	return ok
}

func (s *projectMCPTrustStore) add(key projectMCPTrustKey) {
	s.mu.Lock()
	if s.trusted == nil {
		s.trusted = map[projectMCPTrustKey]struct{}{}
	}
	s.trusted[key] = struct{}{}
	s.mu.Unlock()
}

func projectMCPPolicy(discovery config.MCPDiscovery) string {
	switch strings.ToLower(strings.TrimSpace(discovery.ProjectConfig)) {
	case "allow", "deny":
		return strings.ToLower(strings.TrimSpace(discovery.ProjectConfig))
	default:
		return "confirm"
	}
}

func projectMCPConfigDigest(workspacePath string) (string, bool, error) {
	path := config.ProjectMCPPath(workspacePath)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:]), true, nil
}

func projectMCPServerNames(workspacePath string) ([]string, error) {
	project, err := config.LoadMCPFile(config.ProjectMCPPath(workspacePath))
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(project.MCPServers))
	for name := range project.MCPServers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func (r *Runtime) requireProjectMCPTrust(
	ctx context.Context,
	envReq envelope.Request,
	principal auth.Principal,
	remoteSessionID,
	workspaceName,
	workspacePath string,
) (*mcp.CallToolResult, error) {
	digest, exists, err := projectMCPConfigDigest(workspacePath)
	if err != nil {
		return r.terminalError(envReq, remoteSessionID, workspaceName, "mcp_config_error", err.Error())
	}
	if !exists {
		return nil, nil
	}
	switch projectMCPPolicy(r.cfg.Discovery.MCP) {
	case "allow":
		return nil, nil
	case "deny":
		return r.terminalError(envReq, remoteSessionID, workspaceName, "project_mcp_denied", "project .mcpx/.mcp.json is disabled by policy")
	}
	if strings.TrimSpace(remoteSessionID) == "" {
		return r.terminalError(envReq, "", workspaceName, "remote_session_required", "project MCP execution requires a Remote Session for confirmation")
	}
	if session, getErr := r.remote.Get(ctx, principal, remoteSessionID); getErr == nil && session.ApprovalMode == remotesession.ApprovalModeTrusted {
		return nil, nil
	}
	key := projectMCPTrustKey{RemoteSessionID: remoteSessionID, PrincipalID: principal.ID, ConfigDigest: digest}
	if r.projectMCPTrust.has(key) {
		return nil, nil
	}
	confirmationToken := strings.TrimSpace(stringPayload(envReq.Payload, "confirmation_token"))
	contentKey := strings.Join([]string{"project_mcp", principal.ID, workspacePath, digest}, "\x00")
	if confirmationToken != "" {
		for _, pending := range r.approvals.ListRemoteSession(remoteSessionID) {
			if pending.Tool == "project_mcp" && pending.PrincipalID == principal.ID && pending.ContentKey == contentKey && pending.ConfirmationToken == confirmationToken {
				if _, consumed := r.approvals.Consume(pending.ID); consumed {
					r.projectMCPTrust.add(key)
					return nil, nil
				}
			}
		}
	}
	names, err := projectMCPServerNames(workspacePath)
	if err != nil {
		return r.terminalError(envReq, remoteSessionID, workspaceName, "mcp_config_error", err.Error())
	}
	summary := fmt.Sprintf("execute project MCP configuration %s", filepath.Join(".mcpx", ".mcp.json"))
	pending, err := r.approvals.PutPending(approval.Pending{
		Tool: "project_mcp", Summary: summary, Purpose: envReq.Intent, Scope: "workspace", CommandDigest: digest,
		WorkDir: workspacePath, RequestID: envReq.RequestID, Workspace: workspaceName,
		RemoteSessionID: remoteSessionID, PrincipalID: principal.ID, ContentKey: contentKey,
	})
	if err != nil {
		return r.terminalError(envReq, remoteSessionID, workspaceName, "confirmation_store_error", err.Error())
	}
	message := "项目级 .mcpx/.mcp.json 将在本机启动可执行 stdio MCP Server；请审阅项目配置并明确确认后，使用相同调用参数和 confirmation_token 重试。"
	if confirmationToken != "" {
		message = "你提供的 confirmation_token 未匹配当前项目 MCP 配置；请使用本响应中的完整 token 原样重试。"
	}
	response := envelope.Fail(envelope.StatusNeedConfirmation, envReq.RequestID, workspaceName, map[string]any{
		"confirmation_token": pending.ConfirmationToken, "confirmation_required": true, "confirmation_message": message,
		"config_path": filepath.Join(".mcpx", ".mcp.json"), "config_digest": digest, "servers": names,
	}, "PROJECT_MCP_CONFIRMATION_REQUIRED", "项目 MCP 配置等待用户语义确认")
	response.RemoteSessionID = remoteSessionID
	return r.resultJSON(response)
}
