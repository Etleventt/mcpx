package oauth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"mcpx/internal/logging"
)

func TestAuthorizeLogsDoNotExposeCredentialsOrRedirectSecrets(t *testing.T) {
	var output bytes.Buffer
	logging.Init(logging.Options{Level: "info", Format: "text", Out: &output})
	defer logging.Init(logging.Options{Level: "info"})
	const (
		password    = "operator-password-sensitive"
		state       = "oauth-state-sensitive"
		redirectURI = "https://callback.example/private/path?secret=redirect-sensitive"
	)
	server := NewServer(password, "https://mcp.example.com", make([]byte, 32), 60)
	if err := server.Registry.AddPreregistered("log-test-client", []string{redirectURI}, ""); err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"password":              {password},
		"client_id":             {"log-test-client"},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {strings.Repeat("a", 43)},
		"code_challenge_method": {"S256"},
		"state":                 {state},
		"resource":              {"https://mcp.example.com/mcp"},
		"scope":                 {"mcp"},
	}
	request := httptest.NewRequest(http.MethodPost, MCPOAuthPrefix+"/authorize", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	(&Handler{S: server}).HandleAuthorize(recorder, request)
	if recorder.Code != http.StatusFound {
		t.Fatalf("authorize status=%d", recorder.Code)
	}
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatal("authorization code missing")
	}
	log := output.String()
	if !strings.Contains(log, "redirect_host=callback.example") {
		t.Fatal("safe redirect host missing")
	}
	for _, secret := range []string{password, state, redirectURI, "/private/path", "redirect-sensitive", code} {
		if strings.Contains(log, secret) {
			t.Fatal("authorization log leaked a secret")
		}
	}
}
