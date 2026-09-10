package mcpproxy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcpx/internal/config"
	"mcpx/internal/mcpresult"
)

func remoteFixture(t *testing.T, verify func(*http.Request) bool) *httptest.Server {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "remote-fixture", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "ping", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcpresult.NewText("pong"), nil
	})
	streamable := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{DisableLocalhostProtection: true, Stateless: true})
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !verify(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		streamable.ServeHTTP(w, r)
	}))
}

func TestRemoteStreamableHTTPAuthenticationVariants(t *testing.T) {
	t.Setenv("SUBDESK_TEST_TOKEN", "env-secret-token")
	tests := []struct {
		name   string
		server func(string) config.MCPServer
		verify func(*http.Request) bool
	}{
		{
			name: "structured bearer",
			server: func(endpoint string) config.MCPServer {
				return config.MCPServer{URL: endpoint, Auth: &config.MCPAuthConfig{Type: "bearer", Token: "${SUBDESK_TEST_TOKEN}"}}
			},
			verify: func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer env-secret-token" },
		},
		{
			name: "raw authorization header",
			server: func(endpoint string) config.MCPServer {
				return config.MCPServer{Type: "http", URL: endpoint, Headers: map[string]string{"Authorization": "Bearer raw-secret"}}
			},
			verify: func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer raw-secret" },
		},
		{
			name: "api key header",
			server: func(endpoint string) config.MCPServer {
				return config.MCPServer{URL: endpoint, Auth: &config.MCPAuthConfig{Type: "api_key", In: "header", Name: "X-Xiaomi-Token", Token: "xiaomi-secret"}}
			},
			verify: func(r *http.Request) bool { return r.Header.Get("X-Xiaomi-Token") == "xiaomi-secret" },
		},
		{
			name: "api key query",
			server: func(endpoint string) config.MCPServer {
				return config.MCPServer{URL: endpoint, Auth: &config.MCPAuthConfig{Type: "api_key", In: "query_param", Name: "token", Token: "query-secret"}}
			},
			verify: func(r *http.Request) bool { return r.URL.Query().Get("token") == "query-secret" },
		},
		{
			name: "query already in url",
			server: func(endpoint string) config.MCPServer {
				return config.MCPServer{URL: endpoint + "?access_token=url-secret"}
			},
			verify: func(r *http.Request) bool { return r.URL.Query().Get("access_token") == "url-secret" },
		},
		{
			name:   "no authentication",
			server: func(endpoint string) config.MCPServer { return config.MCPServer{URL: endpoint} },
			verify: func(*http.Request) bool { return true },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := remoteFixture(t, test.verify)
			defer fixture.Close()
			srv := test.server(fixture.URL + "/mcp")
			tools, err := ListTools(context.Background(), srv)
			if err != nil || len(tools) != 1 || tools[0].Name != "ping" {
				t.Fatalf("tools=%+v err=%v", tools, err)
			}
			result, err := CallTool(context.Background(), srv, "ping", map[string]any{})
			if err != nil || result == nil {
				t.Fatalf("call result=%+v err=%v", result, err)
			}
		})
	}
}

func TestCredentialedRemoteRedirectCannotCrossOrigin(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalls.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("credential leaked to redirect target")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/mcp", http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	srv := config.MCPServer{URL: redirect.URL + "/mcp", Auth: &config.MCPAuthConfig{Type: "bearer", Token: "redirect-secret"}}
	_, err := ListTools(context.Background(), srv)
	if err == nil || !strings.Contains(err.Error(), "crossed origin") {
		t.Fatalf("cross-origin redirect err=%v", err)
	}
	if targetCalls.Load() != 0 {
		t.Fatalf("redirect target was contacted %d times", targetCalls.Load())
	}
}

func TestRemoteConfigurationSafetyAndRedaction(t *testing.T) {
	if _, err := buildRemoteRequestConfig(config.MCPServer{URL: "https://example.com/mcp", Auth: &config.MCPAuthConfig{Type: "bearer", Token: "${SUBDESK_MISSING_TOKEN}"}}); err == nil || !strings.Contains(err.Error(), "is not set") {
		t.Fatalf("missing credential environment variable was not rejected: %v", err)
	}
	if _, err := buildRemoteRequestConfig(config.MCPServer{URL: "http://example.com/mcp"}); err == nil {
		t.Fatal("public plaintext HTTP accepted without opt-in")
	}
	if _, err := buildRemoteRequestConfig(config.MCPServer{URL: "http://example.com/mcp", AllowInsecureHTTP: true}); err != nil {
		t.Fatalf("explicit insecure HTTP opt-in rejected: %v", err)
	}
	if _, err := buildRemoteRequestConfig(config.MCPServer{URL: "https://example.com/mcp", Headers: map[string]string{"Bad\nHeader": "x"}}); err == nil {
		t.Fatal("header injection accepted")
	}
	srv := config.MCPServer{URL: "https://example.com/mcp?token=url-secret", Headers: map[string]string{"Authorization": "Bearer header-secret"}, Auth: nil}
	err := redactMCPError(srv, errors.New("failed url-secret header-secret token=url-secret"))
	if strings.Contains(err.Error(), "url-secret") || strings.Contains(err.Error(), "header-secret") {
		t.Fatalf("credential remained in error: %v", err)
	}
}

func TestRemoteDescriptorNeverContainsSecrets(t *testing.T) {
	srv := config.MCPServer{
		URL:     "https://example.com/mcp?access_token=url-secret",
		Headers: map[string]string{"Authorization": "Bearer header-secret", "X-API-Key": "api-secret"},
		Query:   map[string]string{"tenant_token": "query-secret"},
		Auth:    nil,
	}
	manager := NewManager(true, config.MCPFile{MCPServers: map[string]config.MCPServer{"remote": srv}})
	items := manager.List()
	if len(items) != 1 || items[0]["type"] != "streamable-http" || items[0]["endpoint"] != "https://example.com/mcp" {
		t.Fatalf("descriptor=%+v", items)
	}
	raw, _ := json.Marshal(items)
	for _, secret := range []string{"url-secret", "header-secret", "api-secret", "query-secret"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("descriptor leaked %q: %s", secret, raw)
		}
	}
	auth, _ := items[0]["authentication"].(map[string]any)
	if auth["secrets_exposed"] != false {
		t.Fatalf("auth descriptor=%+v", auth)
	}
}

func TestRemoteTransportTypeCompatibilityAliases(t *testing.T) {
	for _, typeName := range []string{"", "http", "streamable-http", "streamable_http"} {
		got, err := remoteTransportType(config.MCPServer{Type: typeName, URL: "https://example.com/mcp"})
		if err != nil || got != "streamable-http" {
			t.Fatalf("type=%q got=%q err=%v", typeName, got, err)
		}
	}
	if got, err := remoteTransportType(config.MCPServer{Type: "sse", URL: "https://example.com/sse"}); err != nil || got != "sse" {
		t.Fatalf("sse got=%q err=%v", got, err)
	}
}

func TestRemoteListToolsTimeoutDoesNotExposeToken(t *testing.T) {
	srv := config.MCPServer{URL: "https://127.0.0.1:1/mcp", Auth: &config.MCPAuthConfig{Type: "bearer", Token: "never-log-this-token"}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := ListTools(ctx, srv)
	if err == nil {
		t.Fatal("unreachable server unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "never-log-this-token") {
		t.Fatalf("token leaked in network error: %v", err)
	}
}
