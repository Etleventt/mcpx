package server

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcpx/internal/envelope"
	"mcpx/internal/filescope"
	"mcpx/internal/mcpresult"
	"mcpx/internal/remotesession"
	"mcpx/internal/security"
)

func (r *Runtime) fileScopeStore() filescope.Store {
	if r.globalCfgPath == "" {
		return filescope.Store{}
	}
	home := filepath.Dir(r.globalCfgPath)
	if real, e := filepath.EvalSymlinks(home); e == nil {
		home = real
	}
	return filescope.Store{Home: home}
}
func (r *Runtime) guardFileScope(name string, next mcp.ToolHandler) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		r.fileScopeMu.Lock()
		p, e := r.fileScopeStore().Load()
		r.fileScopeActive++
		r.fileScopeMu.Unlock()
		defer func() { r.fileScopeMu.Lock(); r.fileScopeActive--; r.fileScopeMu.Unlock() }()
		if e != nil {
			return mcpresult.NewError("文件访问策略无法验证，已拒绝请求。请在本机修复，不会自动切回完全访问。"), nil
		}
		if p.Mode == filescope.Full {
			return next(ctx, req)
		}
		if name == "file_receive" {
			return r.toolFileReceiveRestricted(ctx, req, p)
		}
		return r.restrictedTool(ctx, req, name, p)
	}
}
func restrictedSessionData(s remotesession.Session) map[string]any {
	return map[string]any{"session_id": s.ID, "workspace": s.WorkspaceName, "status": s.Status, "mode": "folders", "file_only": true, "allowed_tools": []string{"session", "session_read", "workspace_read", "source_read", "file_receive", "change"}, "notice": "仅允许指定目录的文件读取、搜索和单文件编辑；终端、外部代理、MCP扩展和旧活动记录不可用。"}
}
func (r *Runtime) restrictedTool(ctx context.Context, req *mcp.CallToolRequest, name string, p filescope.Policy) (*mcp.CallToolResult, error) {
	env, principal, fail := r.remoteRequest(ctx, req)
	if fail != nil {
		return fail, nil
	}
	deny := func(message string) (*mcp.CallToolResult, error) {
		return r.resultJSON(envelope.Fail(envelope.StatusDenied, env.RequestID, env.Workspace, nil, "FILESYSTEM_SCOPE_DENIED", message))
	}
	const unavailable = "仅指定文件夹模式不允许此操作。终端、脚本、外部代理、MCP扩展、截图及完全访问模式的历史结果均已关闭。请在本机客户端切换模式，远程请求不能扩权。"
	if name == "runtime_read" {
		return compactToolResult(map[string]any{"scope_version": 1, "mode": "folders", "file_only": true, "terminal": false, "external_execution": false}, unavailable), nil
	}
	if name == "workspace_read" && publicSelector(req, "view") == "list" {
		entries := []map[string]any{}
		for _, spec := range p.Roots {
			if ws, ok := r.reg.Get(spec.Name); ok && ws.Path == spec.Path {
				entries = append(entries, map[string]any{"name": spec.Name, "path": spec.Path})
			}
		}
		return compactToolResult(map[string]any{"workspaces": entries, "mode": "folders"}, "已读取当前授权的文件夹。"), nil
	}
	if name == "session_read" && publicSelector(req, "view") == "list" {
		list, e := r.remote.List(ctx, principal, remotesession.ListInput{Limit: 100})
		if e != nil {
			return deny("无法读取受限会话。")
		}
		sessions := []map[string]any{}
		for _, s := range list.Sessions {
			if s.BaseTreeDigest == "folders:"+p.Generation {
				sessions = append(sessions, restrictedSessionData(s))
			}
		}
		return compactToolResult(map[string]any{"sessions": sessions}, "仅显示当前隔离范围下的会话。"), nil
	}
	if name == "session" && publicSelector(req, "action") == "open" && env.RemoteSessionID == "" {
		workspace := env.Workspace
		if workspace == "" {
			workspace = stringPayload(env.Payload, "workspace")
		}
		root, spec, e := p.Open(workspace)
		if e != nil {
			return deny("此文件夹未获授权或已被替换。")
		}
		root.Close()
		ws, ok := r.reg.Get(workspace)
		if !ok || ws.Path != spec.Path {
			return deny("文件夹配置已改变，请在本机更新访问范围。")
		}
		id := stringPayload(env.Payload, "client_request_id")
		if id != "" {
			id = p.Generation + ":" + id
		}
		created, e := r.remote.Create(ctx, principal, remotesession.CreateInput{WorkspaceName: spec.Name, WorkspacePath: spec.Path, BaseTreeDigest: "folders:" + p.Generation, Label: "Folder-only session", ApprovalMode: "standard", ClientRequestID: id})
		if e != nil {
			return r.remoteError(env, "", workspace, e)
		}
		return compactToolResult(restrictedSessionData(created.Session), "已创建仅限指定文件夹的会话；请使用完整 session_id。"), nil
	}
	if name != "source_read" && name != "change" && name != "session" && name != "session_read" {
		return deny(unavailable)
	}
	s, e := r.remote.Get(ctx, principal, env.RemoteSessionID)
	if e != nil || s.BaseTreeDigest != "folders:"+p.Generation {
		return deny("此会话不属于当前访问范围。请重新打开受限会话，不能继续读取完全访问模式的历史内容。")
	}
	root, spec, e := p.Open(s.WorkspaceName)
	if e != nil {
		return deny("文件夹授权已失效。")
	}
	defer root.Close()
	ws, ok := r.reg.Get(s.WorkspaceName)
	if !ok || ws.Path != spec.Path || s.WorkspacePath != spec.Path {
		return deny("文件夹已取消授权。")
	}
	if name == "session" && publicSelector(req, "action") == "open" || name == "session_read" && publicSelector(req, "view") == "summary" {
		return compactToolResult(restrictedSessionData(s), "当前受限会话。"), nil
	}
	if name == "source_read" {
		view := publicSelector(req, "view")
		if view == "file" {
			path := stringPayload(env.Payload, "path")
			if security.MatchFile(r.cfg.Security.Files, path) != security.Allow {
				return deny("文件被本机规则拒绝。")
			}
			raw, _, e := filescope.Read(root, path)
			if e != nil {
				return deny("文件不在允许范围内、不是独立普通文件或超过读取限制。")
			}
			if !utf8.Valid(raw) {
				return deny("当前受限文件读取只支持 UTF-8 文本。")
			}
			content := string(raw)
			lines := strings.Split(content, "\n")
			offset, limit := intPayload(env.Payload, "offset"), intPayload(env.Payload, "limit")
			if offset < 0 {
				offset = 0
			}
			if offset > len(lines) {
				offset = len(lines)
			}
			if limit <= 0 || limit > 1000 {
				limit = 200
			}
			end := offset + limit
			if end > len(lines) {
				end = len(lines)
			}
			if publicSelector(req, "mode") != "full" {
				content = strings.Join(lines[offset:end], "\n")
			}
			return compactToolResult(map[string]any{"path": path, "content": content, "sha256": filescope.SHA(raw), "size_bytes": len(raw), "total_lines": len(lines), "offset": offset, "next_offset": end, "truncated": publicSelector(req, "mode") != "full" && end < len(lines), "encoding": "utf-8", "scope": "folders"}, "已在授权目录内读取文件。"), nil
		}
		if view == "list" || view == "search" {
			query := ""
			if view == "search" {
				query = stringPayload(env.Payload, "query")
				if query == "" {
					return deny("请填写搜索内容。")
				}
			}
			result, e := filescope.Scan(root, stringSlicePayload(env.Payload, "paths"), query, boolPayload(env.Payload, "regex"), intPayload(env.Payload, "limit"), func(path string) bool { return security.MatchFile(r.cfg.Security.Files, path) == security.Allow })
			if e != nil {
				return deny(e.Error())
			}
			// Global deny rules also apply to the returned directory/search entries.
			if items, ok := result["files"].([]filescope.Entry); ok {
				out := []filescope.Entry{}
				for _, v := range items {
					if security.MatchFile(r.cfg.Security.Files, v.Path) == security.Allow {
						out = append(out, v)
					}
				}
				result["files"] = out
			}
			if items, ok := result["matches"].([]filescope.Match); ok {
				out := []filescope.Match{}
				for _, v := range items {
					if security.MatchFile(r.cfg.Security.Files, v.Path) == security.Allow {
						out = append(out, v)
					}
				}
				result["matches"] = out
			}
			return compactToolResult(result, "已在授权目录内完成查询。"), nil
		}
		return deny(unavailable)
	}
	if name == "change" {
		if publicSelector(req, "action") != "prepare" || !boolPayload(env.Payload, "apply") || boolPayload(env.Payload, "format") || env.Payload["verify"] != nil {
			return deny("受限模式仅支持不带验证命令或格式化程序的单文件 prepare + apply。")
		}
		if s.Role != "owner" && s.Role != "editor" {
			return deny("当前会话没有写权限。")
		}
		raw, e := json.Marshal(env.Payload["operations"])
		if e != nil {
			return deny("无效文件操作。")
		}
		var ops []filescope.Edit
		if json.Unmarshal(raw, &ops) != nil || len(ops) != 1 {
			return deny("受限模式每次只保存一个文件，支持 create 或 replace_exact。")
		}
		if security.MatchFile(r.cfg.Security.Files, ops[0].Path) != security.Allow {
			return deny("文件被本机规则拒绝。")
		}
		r.fileScopeEdit.Lock()
		result, e := filescope.EditOne(root, ops[0])
		r.fileScopeEdit.Unlock()
		if e != nil {
			return deny(e.Error())
		}
		return compactToolResult(result, "已保存授权目录内的文件；未运行任何程序。"), nil
	}
	return deny(unavailable)
}

// Resource endpoints are another route to old outputs. They are closed in
// restricted mode, including calls from clients with a cached old schema.
func (r *Runtime) checkFileScopeResource() error {
	p, e := r.fileScopeStore().Load()
	if e != nil || p.Mode != filescope.Full {
		return fmt.Errorf("resource unavailable in folder-only mode")
	}
	return nil
}
