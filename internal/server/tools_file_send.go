package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcpx/internal/envelope"
	"mcpx/internal/filescope"
	"mcpx/internal/mcpresult"
	"mcpx/internal/remotesession"
	"mcpx/internal/security"
)

const runtimeFileExportTTL = 5 * time.Minute
const maxRuntimeFileExports = 128

type runtimeFileExport struct {
	File      *os.File
	FileName  string
	MIMEType  string
	Size      int64
	ExpiresAt time.Time
}

type runtimeFileExportStore struct {
	mu    sync.Mutex
	items map[string]runtimeFileExport
	now   func() time.Time
}

func newRuntimeFileExportStore() *runtimeFileExportStore {
	return &runtimeFileExportStore{items: map[string]runtimeFileExport{}, now: time.Now}
}

func (s *runtimeFileExportStore) issue(record runtimeFileExport) (string, time.Time, error) {
	if s == nil || record.File == nil {
		return "", time.Time{}, errors.New("file export unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	if len(s.items) >= maxRuntimeFileExports {
		return "", time.Time{}, errors.New("too many pending file exports")
	}
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", time.Time{}, err
	}
	token := hex.EncodeToString(raw[:])
	record.ExpiresAt = s.now().Add(runtimeFileExportTTL)
	s.items[token] = record
	return token, record.ExpiresAt, nil
}

func (s *runtimeFileExportStore) take(token string) (runtimeFileExport, bool) {
	if s == nil {
		return runtimeFileExport{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	record, ok := s.items[token]
	if !ok {
		return runtimeFileExport{}, false
	}
	delete(s.items, token)
	return record, true
}

func (s *runtimeFileExportStore) pruneLocked() {
	now := s.now()
	for token, record := range s.items {
		if !record.ExpiresAt.After(now) {
			_ = record.File.Close()
			delete(s.items, token)
		}
	}
}

func (s *runtimeFileExportStore) close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, record := range s.items {
		_ = record.File.Close()
		delete(s.items, token)
	}
}

func (r *Runtime) toolFileSend(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	envReq, _, remote, fail := r.changeRequest(ctx, req, true)
	if fail != nil {
		return fail, nil
	}
	root, err := os.OpenRoot(remote.WorkspacePath)
	if err != nil {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "file_send_unavailable", "workspace cannot be opened safely")
	}
	defer root.Close()
	return r.prepareFileExport(envReq, remote, root)
}

func (r *Runtime) toolFileSendRestricted(ctx context.Context, req *mcp.CallToolRequest, policy filescope.Policy) (*mcp.CallToolResult, error) {
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
	return r.prepareFileExport(envReq, remote, root)
}

func (r *Runtime) prepareFileExport(envReq envelope.Request, remote remotesession.Session, root *os.Root) (*mcp.CallToolResult, error) {
	path, _ := envReq.Payload["path"].(string)
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || filepath.IsAbs(path) || filepath.VolumeName(path) != "" || strings.HasPrefix(path, ".."+string(filepath.Separator)) || path == ".." {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "invalid_path", "path must be a workspace-relative file path")
	}
	if security.MatchFile(r.effectiveConfig(remote.WorkspacePath).Security.Files, filepath.ToSlash(path)) != security.Allow {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "denied", "file path denied by local policy")
	}
	file, err := root.Open(path)
	if err != nil {
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "file_not_found", "file could not be opened safely")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maxRuntimeFileReceiveBytes {
		_ = file.Close()
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "file_not_exportable", "only regular files up to the Runtime hard limit can be exported")
	}
	mimeType := mime.TypeByExtension(strings.ToLower(filepath.Ext(path)))
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	token, expiresAt, err := r.fileExports.issue(runtimeFileExport{File: file, FileName: filepath.Base(path), MIMEType: mimeType, Size: info.Size()})
	if err != nil {
		_ = file.Close()
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "file_send_unavailable", "file export capacity is temporarily unavailable")
	}
	base, err := runtimePublicDeviceURL(r.effectiveConfig(remote.WorkspacePath).Auth.OAuth.ServerURL)
	if err != nil {
		if record, ok := r.fileExports.take(token); ok {
			_ = record.File.Close()
		}
		return r.terminalError(envReq, remote.ID, remote.WorkspaceName, "file_send_unavailable", "SubDesk public device URL is unavailable")
	}
	downloadURL := base + "/files/export/" + token
	result, err := r.remoteResult(envReq, remote.ID, remote.WorkspaceName, map[string]any{
		"path": filepath.ToSlash(path), "file_name": filepath.Base(path), "mime_type": mimeType,
		"size_bytes": info.Size(), "download_url": downloadURL, "expires_at": expiresAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return result, err
	}
	link := mcpresult.NewResourceLink(downloadURL, filepath.Base(path), "One-time SubDesk file download", mimeType)
	size := info.Size()
	link.Size = &size
	result.Content = append(result.Content, link)
	return result, nil
}

func runtimePublicDeviceURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("invalid public device URL")
	}
	path := strings.TrimSuffix(parsed.EscapedPath(), "/")
	if path == "" || path == "/" || !strings.HasPrefix(path, "/d/") {
		return "", errors.New("public device URL must contain the device path")
	}
	return "https://" + parsed.Host + path, nil
}

func (r *Runtime) fileTransferHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		const prefix = "/files/export/"
		if !strings.HasPrefix(request.URL.Path, prefix) {
			next.ServeHTTP(writer, request)
			return
		}
		if request.Method != http.MethodGet || request.URL.RawQuery != "" {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		token := strings.TrimPrefix(request.URL.Path, prefix)
		if len(token) != 48 || strings.Contains(token, "/") {
			http.NotFound(writer, request)
			return
		}
		if _, err := hex.DecodeString(token); err != nil {
			http.NotFound(writer, request)
			return
		}
		record, ok := r.fileExports.take(token)
		if !ok {
			http.NotFound(writer, request)
			return
		}
		defer record.File.Close()
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Content-Type", record.MIMEType)
		writer.Header().Set("Content-Length", strconv.FormatInt(record.Size, 10))
		if disposition := mime.FormatMediaType("attachment", map[string]string{"filename": record.FileName}); disposition != "" {
			writer.Header().Set("Content-Disposition", disposition)
		}
		writer.WriteHeader(http.StatusOK)
		written, err := io.CopyN(writer, record.File, record.Size)
		if err != nil || written != record.Size {
			panic(http.ErrAbortHandler)
		}
	})
}
