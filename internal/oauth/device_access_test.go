package oauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"mcpx/internal/accesspolicy"
	"mcpx/internal/logging"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func accessServer(t *testing.T) *Server {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer("original-device-password", "https://device.example", bytes.Repeat([]byte{42}, 32), 3600)
	s.Access = &accesspolicy.Store{Home: home, LegacyPassword: s.Password}
	if err = s.Registry.AddPreregistered("desktop-test", []string{"http://127.0.0.1/callback"}, ""); err != nil {
		t.Fatal(err)
	}
	return s
}
func accessForm() url.Values {
	verifier := strings.Repeat("p", 64)
	sum := sha256.Sum256([]byte(verifier))
	return url.Values{"client_id": {"desktop-test"}, "redirect_uri": {"http://127.0.0.1/callback"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "resource": {"https://device.example/mcp"}, "scope": {"mcp"}, "state": {"synthetic-state"}}
}
func postAccess(t *testing.T, s *Server, endpoint string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", MCPOAuthPrefix+endpoint, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h := &Handler{S: s}
	if endpoint == "/authorize" {
		h.HandleAuthorize(w, r)
	} else {
		h.HandleToken(w, r)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing no-store")
	}
	return w
}
func authorizeAccess(t *testing.T, s *Server, password string) string {
	t.Helper()
	form := accessForm()
	form.Set("password", password)
	w := postAccess(t, s, "/authorize", form)
	if w.Code != 302 {
		t.Fatalf("authorize HTTP %d", w.Code)
	}
	u, e := url.Parse(w.Header().Get("Location"))
	if e != nil {
		t.Fatal("invalid redirect")
	}
	if u.Query().Get("state") != "synthetic-state" || u.Query().Get("code") == "" {
		t.Fatal("missing bound OAuth redirect")
	}
	return u.Query().Get("code")
}
func exchangeAccess(t *testing.T, s *Server, code string) (string, string, int) {
	t.Helper()
	form := accessForm()
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("code_verifier", strings.Repeat("p", 64))
	w := postAccess(t, s, "/token", form)
	if w.Code != 200 {
		t.Fatalf("exchange HTTP %d", w.Code)
	}
	var out struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
		TTL     int    `json:"expires_in"`
	}
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Access == "" || out.Refresh == "" {
		t.Fatal("missing token pair")
	}
	return out.Access, out.Refresh, out.TTL
}
func TestTemporaryHTTPGrantLifecycle(t *testing.T) {
	s := accessServer(t)
	var log bytes.Buffer
	logging.Init(logging.Options{Level: "info", Out: &log})
	defer logging.Init(logging.Options{Level: "info"})
	old, e := s.CreateAccessToken("desktop-test", s.ResourceURL(s.ServerURL), s.ServerURL)
	if e != nil {
		t.Fatal(e)
	}
	status, password, e := s.Access.CreateTemporary()
	if e != nil {
		t.Fatal(e)
	}
	form := accessForm()
	form.Set("password", "wrong-test-password")
	if w := postAccess(t, s, "/authorize", form); w.Code != 401 {
		t.Fatal("wrong credential allowed")
	}
	code := authorizeAccess(t, s, password)
	token, refresh, ttl := exchangeAccess(t, s, code)
	if ttl <= 0 || ttl > 600 {
		t.Fatalf("temporary ttl %d", ttl)
	}
	parsed, _, e := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if e != nil {
		t.Fatal(e)
	}
	expires, e := parsed.Claims.GetExpirationTime()
	if e != nil || expires.Time.After(*status.TemporaryExpiresAt) {
		t.Fatal("temporary JWT outlives grant")
	}
	if !s.ValidateAccessToken(token, s.ServerURL, s.ResourceURL(s.ServerURL)) || !s.ValidateAccessToken(old, s.ServerURL, s.ResourceURL(s.ServerURL)) {
		t.Fatal("temporary creation broke valid authorization")
	}
	form.Set("password", password)
	if w := postAccess(t, s, "/authorize", form); w.Code != 401 {
		t.Fatal("temporary credential replay allowed")
	}
	rotate := url.Values{"grant_type": {"refresh_token"}, "client_id": {"desktop-test"}, "refresh_token": {refresh}, "resource": {s.ResourceURL(s.ServerURL)}}
	w := postAccess(t, s, "/token", rotate)
	if w.Code != 200 {
		t.Fatal("temporary refresh failed")
	}
	var next struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
		TTL     int    `json:"expires_in"`
	}
	if json.Unmarshal(w.Body.Bytes(), &next) != nil || next.TTL > 600 || next.Refresh == "" {
		t.Fatal("refresh lost grant bound")
	}
	if w = postAccess(t, s, "/token", rotate); w.Code != 400 {
		t.Fatal("refresh replay allowed")
	}
	if _, e = s.Access.RevokeTemporary(); e != nil {
		t.Fatal(e)
	}
	if s.ValidateAccessToken(token, s.ServerURL, s.ResourceURL(s.ServerURL)) || s.ValidateAccessToken(next.Access, s.ServerURL, s.ResourceURL(s.ServerURL)) {
		t.Fatal("revoked token accepted")
	}
	rotate.Set("refresh_token", next.Refresh)
	if w = postAccess(t, s, "/token", rotate); w.Code != 400 {
		t.Fatal("revoked refresh accepted")
	}
	if !s.ValidateAccessToken(old, s.ServerURL, s.ResourceURL(s.ServerURL)) {
		t.Fatal("temporary revoke damaged legacy grant")
	}
	for _, secret := range []string{password, code, token, refresh, next.Access, next.Refresh} {
		if strings.Contains(log.String(), secret) {
			t.Fatal("OAuth log leaked credential")
		}
	}
}
func TestTemporaryHTTPExpiryAndFixedRotation(t *testing.T) {
	s := accessServer(t)
	status, password, e := s.Access.CreateTemporary()
	if e != nil {
		t.Fatal(e)
	}
	code := authorizeAccess(t, s, password)
	token, refresh, _ := exchangeAccess(t, s, code)
	s.Access.Now = func() time.Time { return status.TemporaryExpiresAt.Add(time.Second) }
	if s.ValidateAccessToken(token, s.ServerURL, s.ResourceURL(s.ServerURL)) {
		t.Fatal("expired grant validated")
	}
	if _, _, _, e = s.ExchangeRefreshToken(refresh, "desktop-test", ""); e == nil {
		t.Fatal("expired grant refreshed")
	}
	s.Access.Now = nil
	oldCode := authorizeAccess(t, s, s.Password)
	oldToken, oldRefresh, _ := exchangeAccess(t, s, oldCode)
	if _, e = s.Access.SetFixed("replacement-fixed-password"); e != nil {
		t.Fatal(e)
	}
	if s.ValidateAccessToken(oldToken, s.ServerURL, s.ResourceURL(s.ServerURL)) {
		t.Fatal("old password token survived rotation")
	}
	if _, _, _, e = s.ExchangeRefreshToken(oldRefresh, "desktop-test", ""); e == nil {
		t.Fatal("old password refresh survived rotation")
	}
	form := accessForm()
	form.Set("password", s.Password)
	if w := postAccess(t, s, "/authorize", form); w.Code != 401 {
		t.Fatal("old password accepted")
	}
	_ = authorizeAccess(t, s, "replacement-fixed-password")
}
func TestTemporaryHTTPResourceAndPKCEBinding(t *testing.T) {
	s := accessServer(t)
	_, password, e := s.Access.CreateTemporary()
	if e != nil {
		t.Fatal(e)
	}
	form := accessForm()
	form.Set("password", password)
	form.Set("resource", "https://other.example/mcp")
	if w := postAccess(t, s, "/authorize", form); w.Code == 302 {
		t.Fatal("unbound resource allowed")
	}
	code := authorizeAccess(t, s, password)
	form = accessForm()
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("code_verifier", strings.Repeat("x", 64))
	if w := postAccess(t, s, "/token", form); w.Code != 400 {
		t.Fatal("wrong PKCE accepted")
	}
}
func TestAccessMetadataCapability(t *testing.T) {
	s := accessServer(t)
	w := httptest.NewRecorder()
	(&Handler{S: s}).HandleAuthorizationServerMetadata(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(w.Body.String(), `"subdesk_access_policy":1`) {
		t.Fatal("running enforcement capability missing")
	}
}
