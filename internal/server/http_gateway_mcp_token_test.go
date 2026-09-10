package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"mcpx/internal/accesspolicy"
	"mcpx/internal/auth"
	"mcpx/internal/config"
	"mcpx/internal/oauth"
)

func TestGatewayDeviceMCPTokenHeaders(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	osrv := oauth.NewServer("device-access-password", "", make([]byte, 32), 3600)
	osrv.Access = &accesspolicy.Store{Home: home, LegacyPassword: "device-access-password"}
	_, first, err := osrv.Access.GenerateMCPToken()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Auth.Mode = "oauth"
	principals := map[string]bool{}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := auth.PrincipalFromContext(r.Context())
		if !ok || principal.Kind != "mcp_token" || principal.ID == "" {
			t.Fatalf("unexpected principal: %+v ok=%v", principal, ok)
		}
		principals[principal.ID] = true
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(NewGateway(cfg, osrv, inner).Handler())
	defer server.Close()

	call := func(name, value string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, server.URL+"/mcp", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(name, value)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		return res.StatusCode
	}
	if got := call("Authorization", "Bearer "+first); got != http.StatusOK {
		t.Fatalf("bearer status=%d", got)
	}
	if got := call("X-API-Key", first); got != http.StatusOK {
		t.Fatalf("api key status=%d", got)
	}
	if len(principals) != 1 {
		t.Fatalf("same credential mapped to multiple principals: %+v", principals)
	}
	if got := call("Authorization", "Bearer invalid-value"); got != http.StatusUnauthorized {
		t.Fatalf("invalid credential status=%d", got)
	}

	_, second, err := osrv.Access.GenerateMCPToken()
	if err != nil {
		t.Fatal(err)
	}
	if got := call("Authorization", "Bearer "+first); got != http.StatusUnauthorized {
		t.Fatalf("rotated credential status=%d", got)
	}
	if got := call("X-API-Key", second); got != http.StatusOK {
		t.Fatalf("new credential status=%d", got)
	}
	if _, err := osrv.Access.RevokeMCPToken(); err != nil {
		t.Fatal(err)
	}
	if got := call("X-API-Key", second); got != http.StatusUnauthorized {
		t.Fatalf("revoked credential status=%d", got)
	}
}
