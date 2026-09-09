//go:build darwin || linux

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"mcpx/internal/auth"
	"mcpx/internal/config"
	"mcpx/internal/filescope"
	"mcpx/internal/mcpresult"
	"mcpx/internal/remotesession"
)

func scopeFixture(t *testing.T) (*Runtime, string, string, context.Context) {
	t.Helper()
	base, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	home, dir := filepath.Join(base, "runtime"), filepath.Join(base, "project")
	for _, p := range []string{home, dir} {
		if e = os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	t.Setenv("MCPX_HOME", home)
	cfg := config.DefaultConfig()
	cfg.Auth.Mode = "bearer"
	cfg.Auth.Token = "fixture-scope-auth"
	cfg.Workspaces = []config.WorkspaceEntry{{Name: "demo", Path: dir}}
	cfg.Logging.Enabled = false
	cfg.Logging.Dir = filepath.Join(home, "logs")
	if e = config.WriteGlobal(filepath.Join(home, "config.yaml"), cfg); e != nil {
		t.Fatal(e)
	}
	rt, e := New(Options{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { rt.Close() })
	rt.registerTools(mcp.NewServer(&mcp.Implementation{Name: "scope-test", Version: "1"}, nil))
	token, e := rt.fileScopeStore().Ensure()
	if e != nil {
		t.Fatal(e)
	}
	return rt, dir, token, auth.ContextWithAuthorization(context.Background(), "Bearer fixture-scope-auth")
}
func scopeCall(t *testing.T, rt *Runtime, ctx context.Context, name string, args map[string]any) map[string]any {
	t.Helper()
	args["purpose"] = "isolated filesystem scope acceptance"
	handler := rt.toolHandlers[name]
	if handler == nil {
		t.Fatalf("tool %s not registered", name)
	}
	v, e := handler(ctx, mcpresult.Request(args))
	if e != nil {
		t.Fatal(e)
	}
	return decodeToolResult(t, v)
}
func scopeData(t *testing.T, v map[string]any) map[string]any {
	t.Helper()
	if v["status"] != "ok" {
		t.Fatalf("not successful: %+v", v)
	}
	d, ok := v["data"].(map[string]any)
	if !ok {
		t.Fatalf("missing data: %+v", v)
	}
	return d
}
func TestRestrictedToolGateAllowsOnlyBoundedFiles(t *testing.T) {
	rt, dir, _, ctx := scopeFixture(t)
	if e := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("inside-only"), 0600); e != nil {
		t.Fatal(e)
	}
	principal, e := rt.principalFromContext(ctx)
	if e != nil {
		t.Fatal(e)
	}
	old, e := rt.remote.Create(ctx, principal, remotesession.CreateInput{WorkspaceName: "demo", WorkspacePath: dir, Label: "old-full"})
	if e != nil {
		t.Fatal(e)
	}
	p, e := rt.fileScopeStore().Save(filescope.Folders, []filescope.RootSpec{{Name: "demo", Path: dir}})
	if e != nil {
		t.Fatal(e)
	}
	opened := scopeData(t, scopeCall(t, rt, ctx, "session", map[string]any{"action": "open", "workspace": "demo"}))
	id, _ := opened["session_id"].(string)
	if id == "" {
		t.Fatal("no session")
	}
	read := scopeData(t, scopeCall(t, rt, ctx, "source_read", map[string]any{"session_id": id, "view": "file", "path": "hello.txt", "mode": "full"}))
	if read["content"] != "inside-only" {
		t.Fatalf("bad read %+v", read)
	}
	for _, path := range []string{"../runtime/config.yaml", rt.globalCfgPath, "/etc/passwd"} {
		v := scopeCall(t, rt, ctx, "source_read", map[string]any{"session_id": id, "view": "file", "path": path})
		if v["status"] == "ok" {
			t.Fatalf("escape accepted %s", path)
		}
	}
	for _, name := range []string{"command_run", "task", "task_read", "operation_batch", "extension_call", "extension_discover", "runtime_read", "workspace_read", "session_read", "artifact", "change_read"} {
		if name == "runtime_read" || name == "workspace_read" || name == "session_read" {
			continue
		}
		if rt.toolHandlers[name] == nil {
			continue
		}
		v := scopeCall(t, rt, ctx, name, map[string]any{"session_id": id, "action": "run", "view": "logs", "command": "echo must-not-run"})
		if v["status"] == "ok" {
			t.Fatalf("unsafe tool accepted %s %+v", name, v)
		}
	}
	for name := range rt.toolHandlers {
		switch name {
		case "session", "session_read", "workspace_read", "source_read", "change", "runtime_read":
			continue
		}
		v := scopeCall(t, rt, ctx, name, map[string]any{"session_id": id})
		if v["status"] == "ok" {
			t.Fatalf("unreviewed tool not default-denied: %s", name)
		}
	}
	oldRead := scopeCall(t, rt, ctx, "session_read", map[string]any{"session_id": old.Session.ID, "view": "summary"})
	if oldRead["status"] == "ok" {
		t.Fatal("old full history allowed")
	}
	if _, e := rt.resourceArtifact(ctx, &mcp.ReadResourceRequest{}); e == nil {
		t.Fatal("resource route not denied before parse")
	}
	if _, e := rt.resourceTaskLogs(ctx, &mcp.ReadResourceRequest{}); e == nil {
		t.Fatal("logs resource accessible")
	}
	changed := scopeData(t, scopeCall(t, rt, ctx, "change", map[string]any{"session_id": id, "action": "prepare", "apply": true, "operations": []map[string]any{{"operation": "create", "path": "new.txt", "content": "created safely"}}}))
	if changed["applied"] != true {
		t.Fatal("safe write not applied")
	}
	if _, e = rt.fileScopeStore().Save(filescope.Folders, []filescope.RootSpec{{Name: "demo", Path: dir}}); e != nil {
		t.Fatal(e)
	}
	v := scopeCall(t, rt, ctx, "source_read", map[string]any{"session_id": id, "view": "file", "path": "hello.txt"})
	if v["status"] == "ok" {
		t.Fatal("session survived changed scope generation")
	}
	_ = p
}
func TestLocalScopeControlRejectsRemoteCrossOriginAndStaleWrites(t *testing.T) {
	rt, dir, token, _ := scopeFixture(t)
	handler := rt.fileScopeHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(418) }))
	do := func(method, body, bearer, origin, host, remote string, forward bool) *httptest.ResponseRecorder {
		q := httptest.NewRequest(method, "http://127.0.0.1:9090/local/filesystem-scope", strings.NewReader(body))
		q.RemoteAddr = remote
		q.Host = host
		q.Header.Set("Authorization", bearer)
		if origin != "" {
			q.Header.Set("Origin", origin)
		}
		if forward {
			q.Header.Set("X-Forwarded-Host", "hub.example")
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, q)
		return w
	}
	for _, tc := range []struct {
		token, origin, host, remote string
		forward                     bool
	}{{"bad", "", "127.0.0.1:9090", "127.0.0.1:10", false}, {"Bearer " + token, "https://evil.test", "127.0.0.1:9090", "127.0.0.1:10", false}, {"Bearer " + token, "", "evil.test", "127.0.0.1:10", false}, {"Bearer " + token, "", "127.0.0.1:9090", "192.0.2.1:10", false}, {"Bearer " + token, "", "127.0.0.1:9090", "127.0.0.1:10", true}, {token, "", "127.0.0.1:9090", "127.0.0.1:10", false}} {
		w := do("GET", "", tc.token, tc.origin, tc.host, tc.remote, tc.forward)
		if w.Code == 200 {
			t.Fatal("unsafe local control admitted")
		}
	}
	w := do("GET", "", "Bearer "+token, "", "127.0.0.1:9090", "127.0.0.1:10", false)
	if w.Code != 200 {
		t.Fatalf("local status %d", w.Code)
	}
	if bytes.Contains(w.Body.Bytes(), []byte(token)) {
		t.Fatal("management token disclosed")
	}
	var status map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &status); e != nil {
		t.Fatal(e)
	}
	body, _ := json.Marshal(map[string]any{"mode": "folders", "expected_digest": status["digest"], "confirm": true, "roots": []filescope.RootSpec{{Name: "demo", Path: dir}}})
	rt.fileScopeActive = 1
	w = do("POST", string(body), "Bearer "+token, "", "127.0.0.1:9090", "127.0.0.1:10", false)
	if w.Code != 409 {
		t.Fatal("scope changed during active request")
	}
	rt.fileScopeActive = 0
	w = do("POST", string(body), "Bearer "+token, "", "127.0.0.1:9090", "127.0.0.1:10", false)
	if w.Code != 200 {
		t.Fatalf("local setting denied %d %s", w.Code, w.Body.String())
	}
	w = do("POST", string(body), "Bearer "+token, "", "127.0.0.1:9090", "127.0.0.1:10", false)
	if w.Code != 409 {
		t.Fatal("stale scope write accepted")
	}
}
