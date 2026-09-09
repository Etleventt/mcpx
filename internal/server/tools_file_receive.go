package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcpx/internal/envelope"
	"mcpx/internal/filescope"
	"mcpx/internal/remotesession"
	"mcpx/internal/security"
)

const maxRuntimeFileReceiveBytes int64 = 4 << 30

type chatFileInput struct {
	DownloadURL string
	FileID      string
	MIMEType    string
	FileName    string
}

func (r *Runtime) toolFileReceive(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	envReq, _, remote, fail := r.changeRequest(ctx, req, true)
	if fail != nil {
		return fail, nil
	}
	root, err := os.OpenRoot(remote.WorkspacePath)
	if err != nil {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "file_receive_unavailable", "workspace cannot be opened safely")
	}
	defer root.Close()
	return r.receiveFileIntoRoot(ctx, envReq, remote, root)
}

func (r *Runtime) toolFileReceiveRestricted(ctx context.Context, req *mcp.CallToolRequest, policy filescope.Policy) (*mcp.CallToolResult, error) {
	envReq, _, remote, fail := r.changeRequest(ctx, req, true)
	if fail != nil {
		return fail, nil
	}
	if remote.BaseTreeDigest != "folders:"+policy.Generation {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "FILESYSTEM_SCOPE_DENIED", "此会话不属于当前文件夹访问范围")
	}
	root, spec, err := policy.Open(remote.WorkspaceName)
	if err != nil {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "FILESYSTEM_SCOPE_DENIED", "文件夹授权已失效")
	}
	defer root.Close()
	workspace, ok := r.reg.Get(remote.WorkspaceName)
	if !ok || workspace.Path != spec.Path || remote.WorkspacePath != spec.Path {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "FILESYSTEM_SCOPE_DENIED", "文件夹已取消授权")
	}
	return r.receiveFileIntoRoot(ctx, envReq, remote, root)
}

func (r *Runtime) receiveFileIntoRoot(ctx context.Context, envReq envelope.Request, remote remotesession.Session, root *os.Root) (*mcp.CallToolResult, error) {
	path, _ := envReq.Payload["path"].(string)
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || filepath.IsAbs(path) || filepath.VolumeName(path) != "" || strings.HasPrefix(path, ".."+string(filepath.Separator)) || path == ".." {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "invalid_path", "path must be a workspace-relative file path")
	}
	if security.MatchFile(r.effectiveConfig(remote.WorkspacePath).Security.Files, filepath.ToSlash(path)) != security.Allow {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "denied", "file path denied by local policy")
	}
	input, err := parseChatFileInput(envReq.Payload["file"])
	if err != nil {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "invalid_file", err.Error())
	}
	cfg := r.effectiveConfig(remote.WorkspacePath)
	if err := validateRelayFileURL(input.DownloadURL, cfg.Auth.OAuth.ServerURL); err != nil {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "invalid_file_source", err.Error())
	}
	if _, err := root.Stat(path); err == nil {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "file_exists", "destination already exists; SubDesk does not overwrite received files")
	} else if !os.IsNotExist(err) {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "invalid_path", "destination cannot be verified")
	}
	parent := filepath.Dir(path)
	if parent != "." {
		if err := root.MkdirAll(parent, 0o700); err != nil {
			return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "create_parent_failed", "destination folder cannot be created safely")
		}
	}
	tempName, err := receiveTempName(parent)
	if err != nil {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "temporary_file_failed", "temporary file could not be prepared")
	}
	temporary, err := root.OpenFile(tempName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "temporary_file_failed", "temporary file could not be created safely")
	}
	published := false
	defer func() {
		_ = temporary.Close()
		if !published {
			_ = root.Remove(tempName)
		}
	}()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, input.DownloadURL, nil)
	if err != nil {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "invalid_file_source", "file relay URL is invalid")
	}
	request.Header.Set("User-Agent", "SubDesk-Runtime-FileReceive/1")
	client := &http.Client{Timeout: 15 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "file_receive_failed", "file relay could not be read")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "file_receive_failed", fmt.Sprintf("file relay returned HTTP %d", response.StatusCode))
	}
	if response.ContentLength > maxRuntimeFileReceiveBytes {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "file_too_large", "file exceeds the Runtime hard safety limit")
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, hash), io.LimitReader(response.Body, maxRuntimeFileReceiveBytes+1))
	if copyErr != nil || written > maxRuntimeFileReceiveBytes {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "file_receive_failed", "file transfer was interrupted or exceeded its limit")
	}
	if response.ContentLength >= 0 && written != response.ContentLength {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "file_receive_failed", "file transfer ended before the declared size")
	}
	if err := temporary.Sync(); err != nil {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "file_receive_failed", "received file could not be synced")
	}
	if err := temporary.Close(); err != nil {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "file_receive_failed", "received file could not be closed")
	}
	if err := root.Link(tempName, path); err != nil {
		if _, statErr := root.Stat(path); statErr == nil {
			return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "file_exists", "destination appeared during transfer; received file was not published")
		}
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "file_receive_failed", "received file could not be published atomically")
	}
	_ = root.Remove(tempName)
	published = true
	digest := hex.EncodeToString(hash.Sum(nil))
	return r.remoteResult(envReq, remote.ID, remote.WorkspaceName, map[string]any{
		"path": filepath.ToSlash(path), "size_bytes": written, "sha256": digest,
		"file_id": input.FileID, "file_name": input.FileName, "mime_type": input.MIMEType,
	})
}

func parseChatFileInput(value any) (chatFileInput, error) {
	file, ok := value.(map[string]any)
	if !ok {
		return chatFileInput{}, fmt.Errorf("file input is required")
	}
	input := chatFileInput{}
	input.DownloadURL, _ = file["download_url"].(string)
	input.FileID, _ = file["file_id"].(string)
	input.MIMEType, _ = file["mime_type"].(string)
	input.FileName, _ = file["file_name"].(string)
	if len(input.DownloadURL) == 0 || len(input.DownloadURL) > 8192 || len(input.FileID) == 0 || len(input.FileID) > 512 || len(input.FileName) > 1024 || len(input.MIMEType) > 256 {
		return chatFileInput{}, fmt.Errorf("file input is incomplete or too large")
	}
	return input, nil
}

func validateRelayFileURL(raw, serverURL string) error {
	source, err := url.Parse(raw)
	if err != nil || source.Scheme != "https" || source.Host == "" || source.User != nil || source.RawQuery != "" || source.Fragment != "" {
		return fmt.Errorf("file source must be the one-time HTTPS SubDesk relay URL")
	}
	base, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil || base.Scheme != "https" || base.Host == "" || !strings.EqualFold(source.Host, base.Host) {
		return fmt.Errorf("file source is not on this device's SubDesk origin")
	}
	basePath := strings.TrimSuffix(base.EscapedPath(), "/")
	if basePath != "" && basePath != "/" {
		if !strings.HasPrefix(source.EscapedPath(), basePath+"/files/") {
			return fmt.Errorf("file source is outside this device's transfer path")
		}
	} else if !strings.HasPrefix(source.EscapedPath(), "/d/") || !strings.Contains(source.EscapedPath(), "/files/") {
		return fmt.Errorf("file source is outside the SubDesk transfer path")
	}
	return nil
}

func receiveTempName(parent string) (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	name := ".subdesk-receive-" + hex.EncodeToString(raw[:])
	if parent == "." {
		return name, nil
	}
	return filepath.Join(parent, name), nil
}
