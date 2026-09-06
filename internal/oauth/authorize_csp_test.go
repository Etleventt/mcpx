package oauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthorizeCSPContainsOnlyValidatedSafeCallbackOrigin(t *testing.T) {
	for _, raw := range []string{"javascript:alert(1)", "https://bad.example;script-src/unsafe", "https://user@client.example/callback", "http://untrusted.example/callback", "https://client.example/\r\n"} {
		got := authorizePageCSP(raw)
		if !strings.Contains(got, "form-action 'self';") || !strings.Contains(got, "script-src 'none'") {
			t.Fatalf("unsafe callback policy for %q: %q", raw, got)
		}
	}
	for _, raw := range []string{"https://client.example/callback?secret=not-in-policy", "http://127.0.0.1:3333/callback", "http://[::1]:3333/callback"} {
		got := authorizePageCSP(raw)
		if strings.Contains(got, "secret=") || strings.Contains(got, "form-action 'self';") {
			t.Fatalf("invalid safe callback policy: %q", got)
		}
	}
}

func TestAuthorizePostRejectsOversizedInput(t *testing.T) {
	server := NewServer("fixture-password", "https://runtime.example", make([]byte, 32), 60)
	r := httptest.NewRequest(http.MethodPost, "/mcp/oauth/authorize", strings.NewReader("password="+strings.Repeat("x", maxOAuthBody+1)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	(&Handler{S: server}).HandleAuthorize(w, r)
	if w.Code != http.StatusBadRequest || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("oversized authorize status=%d", w.Code)
	}
}
