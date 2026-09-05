package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"mcpx/internal/config"
	"mcpx/internal/logging"
)

func TestLogStartupCredentialsRedactsConfiguredValues(t *testing.T) {
	var output bytes.Buffer
	logging.Init(logging.Options{Level: "info", Format: "text", Out: &output})
	defer logging.Init(logging.Options{Level: "info"})
	cfg := config.DefaultConfig()
	cfg.Auth.Mode = "dual"
	cfg.Auth.Token = "bearer-for-local-dev"
	cfg.Auth.OAuth.Password = "oauth-password-for-local-dev"
	logStartupCredentials(cfg, true, "v0.1.0-test")
	log := output.String()
	for _, value := range []string{"startup credentials", "version=v0.1.0-test", "token_configured=true", "oauth_password_configured=true"} {
		if !strings.Contains(log, value) {
			t.Fatalf("startup credential log missing %q: %s", value, log)
		}
	}
	for _, secret := range []string{cfg.Auth.Token, cfg.Auth.OAuth.Password} {
		if strings.Contains(log, secret) {
			t.Fatal("startup log leaked a credential")
		}
	}
}

func TestDeniedAuthLogDoesNotExposeBearerPrefix(t *testing.T) {
	var output bytes.Buffer
	logging.Init(logging.Options{Level: "info", Format: "text", Out: &output})
	defer logging.Init(logging.Options{Level: "info"})
	cfg := config.DefaultConfig()
	cfg.Auth.Mode = "bearer"
	cfg.Auth.Token = "expected-credential"
	called := false
	gateway := NewGateway(cfg, nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	request := httptest.NewRequest(http.MethodPost, "http://localhost/mcp", nil)
	request.Header.Set("Authorization", "Bearer abcdefg-secret-value")
	response := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || called {
		t.Fatalf("authentication boundary changed: status=%d called=%v", response.Code, called)
	}
	log := output.String()
	for _, secret := range []string{"abcdefg", "secret-value", "auth_prefix", cfg.Auth.Token} {
		if strings.Contains(log, secret) {
			t.Fatal("denied-auth log exposed a credential or its prefix")
		}
	}
}
