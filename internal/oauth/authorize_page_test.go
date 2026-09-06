package oauth

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var inputTagPattern = regexp.MustCompile(`(?i)<input\b[^>]*>`)
var attributePattern = regexp.MustCompile(`([[:alnum:]_-]+)\s*=\s*"([^"]*)"`)

func TestAuthorizePage(t *testing.T) {
	const (
		password    = "device-access-passphrase"
		clientID    = `client-"<script>alert(1)</script>`
		clientName  = `团队助手 <img src=x onerror=alert(1)>`
		redirectURI = "https://client.example/callback?next=%3Cdone%3E"
		challenge   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
		state       = `state-"<tag>`
		resource    = `https://runtime.example/d/DEVICE/mcp?x="<tag>`
		scope       = `mcp tools:"<admin>`
	)
	server := NewServer(password, "https://runtime.example/d/DEVICE", make([]byte, 32), 60)
	if err := server.Registry.AddPreregistered(clientID, []string{redirectURI}, ""); err != nil {
		t.Fatal(err)
	}
	client, _ := server.Registry.Get(clientID)
	client.ClientName = clientName

	requestURL := MCPOAuthPrefix + "/authorize?" + url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
		"resource":              {resource},
		"scope":                 {scope},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, "https://untrusted.invalid"+requestURL, nil)
	req.Host = "attacker.invalid"
	rec := httptest.NewRecorder()
	(&Handler{S: server}).HandleAuthorize(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	for header, want := range map[string]string{
		"Cache-Control":           "no-store",
		"Content-Security-Policy": "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://client.example; frame-ancestors 'none'; base-uri 'none'",
		"Referrer-Policy":         "no-referrer",
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s=%q, want %q", header, got, want)
		}
	}

	body := rec.Body.String()
	if strings.Contains(body, "%%") || !strings.Contains(body, "width:min(100%,620px)") {
		t.Fatal("authorization page contains invalid percentage CSS")
	}
	fields, action := parseAuthorizeForm(t, body)
	if action != "https://runtime.example/d/DEVICE/mcp/oauth/authorize" {
		t.Errorf("form action=%q", action)
	}
	wantFields := map[string]string{
		"client_id": clientID, "redirect_uri": redirectURI,
		"code_challenge": challenge, "code_challenge_method": "S256",
		"state": state, "resource": resource, "scope": scope,
	}
	for name, want := range wantFields {
		if got := fields[name]; got != want {
			t.Errorf("field %s=%q, want %q", name, got, want)
		}
	}
	if fields["password"] != "" {
		t.Errorf("password field must initially be empty")
	}
	for _, want := range []string{
		"设备访问口令", "不要输入平台登录密码", "不要输入 Device Token",
		"普通 HTTPS 中转并非端到端加密", "客户端", "资源", "权限",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	for _, unsafe := range []string{clientName, clientID, resource, scope} {
		if strings.Contains(body, unsafe) {
			t.Errorf("page contains unescaped dynamic value %q", unsafe)
		}
	}
}

func TestAuthorizeFormActionCompatibility(t *testing.T) {
	const redirectURI = "https://client.example/callback"
	for _, tc := range []struct {
		name       string
		issuer     string
		host       string
		wantAction string
	}{
		{name: "设备前缀来自可信issuer", issuer: "https://runtime.example/d/DEVICE", host: "attacker.invalid", wantAction: "https://runtime.example/d/DEVICE/mcp/oauth/authorize"},
		{name: "旧版issuer无前缀", issuer: "https://runtime.example", host: "attacker.invalid", wantAction: "https://runtime.example/mcp/oauth/authorize"},
		{name: "未配置issuer沿用内部路径但不采用Host", issuer: "", host: "attacker.invalid", wantAction: MCPOAuthPrefix + "/authorize"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := NewServer("pass", tc.issuer, make([]byte, 32), 60)
			if err := server.Registry.AddPreregistered("client", []string{redirectURI}, ""); err != nil {
				t.Fatal(err)
			}
			query := url.Values{
				"client_id": {"client"}, "redirect_uri": {redirectURI},
				"code_challenge": {strings.Repeat("a", 43)}, "code_challenge_method": {"S256"},
			}.Encode()
			req := httptest.NewRequest(http.MethodGet, "https://internal.invalid"+MCPOAuthPrefix+"/authorize?"+query, nil)
			req.Host = tc.host
			rec := httptest.NewRecorder()
			(&Handler{S: server}).HandleAuthorize(rec, req)
			_, action := parseAuthorizeForm(t, rec.Body.String())
			if action != tc.wantAction {
				t.Fatalf("action=%q, want %q", action, tc.wantAction)
			}
			if strings.Contains(action, tc.host) {
				t.Fatalf("action trusts request Host: %q", action)
			}
		})
	}
}

func parseAuthorizeForm(t *testing.T, document string) (map[string]string, string) {
	t.Helper()
	formStart := strings.Index(strings.ToLower(document), "<form")
	if formStart < 0 {
		t.Fatal("form element missing")
	}
	formEnd := strings.Index(document[formStart:], ">")
	if formEnd < 0 {
		t.Fatal("form start tag is malformed")
	}
	formAttrs := parseHTMLAttributes(document[formStart : formStart+formEnd+1])
	fields := make(map[string]string)
	for _, tag := range inputTagPattern.FindAllString(document, -1) {
		attrs := parseHTMLAttributes(tag)
		if name := attrs["name"]; name != "" {
			fields[html.UnescapeString(name)] = html.UnescapeString(attrs["value"])
		}
	}
	return fields, html.UnescapeString(formAttrs["action"])
}

func parseHTMLAttributes(tag string) map[string]string {
	attrs := make(map[string]string)
	for _, match := range attributePattern.FindAllStringSubmatch(tag, -1) {
		attrs[strings.ToLower(match[1])] = match[2]
	}
	return attrs
}
