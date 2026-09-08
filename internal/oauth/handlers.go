package oauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"mcpx/internal/accesspolicy"
	"net/http"
	"net/url"
	"strings"

	"mcpx/internal/logging"
)

const maxOAuthBody = 8192

// Handler serves OAuth HTTP endpoints.
type Handler struct {
	S *Server
}

// OriginFromRequest builds scheme://host from the request.
func OriginFromRequest(r *http.Request, trustProxy bool) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if trustProxy {
		if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
			scheme = strings.Split(p, ",")[0]
			scheme = strings.TrimSpace(scheme)
		}
		if h := r.Header.Get("X-Forwarded-Host"); h != "" {
			host = strings.TrimSpace(strings.Split(h, ",")[0])
		}
	}
	return scheme + "://" + host
}

// HandleProtectedResourceMetadata RFC9728.
func (h *Handler) HandleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	origin := h.S.EffectiveIssuer(OriginFromRequest(r, false))
	resource := h.S.ResourceURL(origin)
	body := map[string]any{
		"resource":                 resource,
		"authorization_servers":    []string{origin},
		"scopes_supported":         []string{DefaultScope},
		"bearer_methods_supported": []string{"header"},
	}
	writeJSON(w, http.StatusOK, body)
}

// OAuth path prefix under /mcp — preferred for reverse proxies that only
// forward the MCP path tree cleanly (Cloudflare/Caddy path rules).
const MCPOAuthPrefix = "/mcp/oauth"

// HandleAuthorizationServerMetadata RFC8414.
// Endpoints are advertised under /mcp/oauth/* so DCR/authorize/token share the
// same public path prefix as the MCP resource (helps 内网穿透 / CDN allowlists).
func (h *Handler) HandleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	origin := h.S.EffectiveIssuer(OriginFromRequest(r, false))
	body := map[string]any{
		"issuer":                                origin,
		"authorization_endpoint":                origin + MCPOAuthPrefix + "/authorize",
		"token_endpoint":                        origin + MCPOAuthPrefix + "/token",
		"registration_endpoint":                 origin + MCPOAuthPrefix + "/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"},
		"scopes_supported":                      []string{DefaultScope},
		// Explicit capability flag some clients check before attempting DCR.
		"registration_endpoint_auth_methods_supported": []string{"none"},
		// OpenAI ChatGPT / MCP clients prefer CIMD when advertised (client_id is an HTTPS URL).
		"client_id_metadata_document_supported": true,
	}
	if h.S.Access != nil {
		body["subdesk_access_policy"] = 1
	}
	writeJSON(w, http.StatusOK, body)
}

// HandleRegister handles POST /mcp/oauth/register.
func (h *Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxOAuthBody))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "cannot read body")
		return
	}
	var meta map[string]any
	if err := json.Unmarshal(raw, &meta); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid JSON")
		return
	}
	out, err := h.S.Registry.Register(meta)
	if err != nil {
		logging.L().Info("oauth register",
			"component", "oauth", "error", err.Error())
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}
	cid, _ := out["client_id"].(string)
	nURIs := 0
	if uris, ok := out["redirect_uris"].([]string); ok {
		nURIs = len(uris)
	}
	logging.L().Info("oauth register",
		"component", "oauth", "client_id", cid,
		"redirect_uris_count", nURIs, "ok", true)
	writeJSON(w, http.StatusCreated, out)
}

// HandleAuthorize handles GET/POST /mcp/oauth/authorize.
func (h *Handler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	r.Body = http.MaxBytesReader(w, r.Body, maxOAuthBody)
	switch r.Method {
	case http.MethodGet:
		h.authorizeGet(w, r)
	case http.MethodPost:
		h.authorizePost(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) authorizeGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	challenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")
	state := q.Get("state")
	resource := q.Get("resource")
	scope := q.Get("scope")
	if scope == "" {
		scope = DefaultScope
	}
	if err := h.validateAuthorizeParams(clientID, redirectURI, challenge, method); err != nil {
		logging.L().Info("oauth authorize",
			"component", "oauth", "method", "GET", "client_id", clientID,
			"redirect_host", redirectHost(redirectURI), "has_state", q.Get("state") != "",
			"state_len", len(q.Get("state")), "resource", resource,
			"scope", scope, "error", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	logging.L().Info("oauth authorize",
		"component", "oauth", "method", "GET", "client_id", clientID,
		"redirect_host", redirectHost(redirectURI), "has_state", state != "",
		"state_len", len(state), "resource", resource,
		"scope", scope, "ok", true)
	c, _ := h.S.ResolveClient(clientID)
	name := clientID
	if c != nil && c.ClientName != "" {
		name = c.ClientName
	}
	issuer := h.S.EffectiveIssuer("")
	formAction := authorizeFormAction(issuer)
	displayResource := resource
	if displayResource == "" && issuer != "" {
		displayResource = h.S.ResourceURL(issuer)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", authorizePageCSP(redirectURI))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	_ = authorizePageTemplate.Execute(w, authorizePageData{
		ClientName: name, ClientID: clientID, RedirectURI: redirectURI,
		CodeChallenge: challenge, CodeChallengeMethod: method, State: state,
		Resource: resource, DisplayResource: displayResource, Scope: scope,
		FormAction: formAction,
	})
}

// Called only after the client and exact redirect URI have been validated.
// Chromium checks form-action again on the OAuth redirect after the POST.
func authorizePageCSP(redirectURI string) string {
	form := "'self'"
	if target, err := url.Parse(redirectURI); err == nil && target.User == nil && target.Host != "" {
		loopback := target.Hostname() == "localhost" || target.Hostname() == "127.0.0.1" || target.Hostname() == "::1"
		origin := target.Scheme + "://" + target.Host
		if (target.Scheme == "https" || (target.Scheme == "http" && loopback)) && !strings.ContainsAny(origin, " \t\r\n;'\"<>\\") {
			form += " " + origin
		}
	}
	return "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; form-action " + form + "; frame-ancestors 'none'; base-uri 'none'"
}

func authorizeFormAction(issuer string) string {
	if issuer == "" {
		return MCPOAuthPrefix + "/authorize"
	}
	return trimSlash(issuer) + MCPOAuthPrefix + "/authorize"
}

func (h *Handler) authorizePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	password := r.FormValue("password")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	challenge := r.FormValue("code_challenge")
	method := r.FormValue("code_challenge_method")
	state := r.FormValue("state")
	resource := r.FormValue("resource")
	scope := r.FormValue("scope")
	if err := h.validateAuthorizeParams(clientID, redirectURI, challenge, method); err != nil {
		logging.L().Info("oauth authorize",
			"component", "oauth", "method", "POST", "client_id", clientID,
			"redirect_host", redirectHost(redirectURI), "has_state", state != "",
			"state_len", len(state), "error", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if resource == "" {
		origin := h.S.EffectiveIssuer(OriginFromRequest(r, false))
		resource = h.S.ResourceURL(origin)
	}
	code, err := h.S.AuthorizeCredential(password, clientID, redirectURI, challenge, method, resource, scope)
	if err != nil {
		status := http.StatusUnauthorized
		if errors.Is(err, accesspolicy.ErrLimited) {
			status = http.StatusTooManyRequests
			w.Header().Set("Retry-After", "60")
		}
		http.Error(w, "设备访问口令无效、已过期或暂时不可用，请在本机检查后重试。", status)
		return
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "bad redirect", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	logging.L().Info("oauth authorize redirect",
		"component", "oauth", "client_id", clientID,
		"redirect_host", u.Host, "has_state", state != "",
		"state_len", len(state), "code_issued", code != "")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func redirectHost(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return "invalid"
	}
	return parsed.Host
}

func (h *Handler) validateAuthorizeParams(clientID, redirectURI, challenge, method string) error {
	if clientID == "" || redirectURI == "" || challenge == "" {
		return fmt.Errorf("missing client_id, redirect_uri, or code_challenge")
	}
	if method != "" && method != "S256" {
		return fmt.Errorf("code_challenge_method must be S256")
	}
	if !h.S.AcceptsClientRedirect(clientID, redirectURI) {
		return fmt.Errorf("unknown client or redirect_uri")
	}
	if !ValidChallenge(challenge) {
		return fmt.Errorf("invalid code_challenge")
	}
	return nil
}

// HandleToken handles POST /mcp/oauth/token.
func (h *Handler) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, maxOAuthBody)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "bad form")
		return
	}
	grant := r.FormValue("grant_type")
	if grant != "authorization_code" && grant != "refresh_token" {
		logging.L().Info("oauth token",
			"component", "oauth", "grant_type", grant,
			"error", "unsupported grant type")
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code or refresh_token")
		return
	}
	clientID, clientSecret, authMethod := h.clientAuth(r)
	if clientID == "" {
		logging.L().Info("oauth token",
			"component", "oauth", "error", "missing client_id")
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "missing client_id")
		return
	}
	if !h.S.AuthenticatesClient(clientID, clientSecret, authMethod) {
		// try registered method from DCR/CIMD when basic/post mismatch
		c, err := h.S.ResolveClient(clientID)
		if err != nil || c == nil {
			logging.L().Info("oauth token",
				"component", "oauth", "client_id", clientID,
				"auth_method", authMethod, "error", "unknown client")
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
			return
		}
		if !h.S.AuthenticatesClient(clientID, clientSecret, c.TokenEndpointAuthMethod) {
			logging.L().Info("oauth token",
				"component", "oauth", "client_id", clientID,
				"auth_method", authMethod, "error", "client authentication failed")
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
			return
		}
	}
	if grant == "refresh_token" {
		refreshToken := r.FormValue("refresh_token")
		resource := r.FormValue("resource")
		tok, ttl, nextRefresh, err := h.S.ExchangeRefreshToken(refreshToken, clientID, resource)
		if err != nil {
			logging.L().Info("oauth token",
				"component", "oauth", "client_id", clientID,
				"auth_method", authMethod, "grant_type", "refresh_token",
				"error", err.Error())
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
			return
		}
		logging.L().Info("oauth token",
			"component", "oauth", "client_id", clientID,
			"auth_method", authMethod, "grant_type", "refresh_token", "ok", true)
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":  tok,
			"token_type":    "Bearer",
			"expires_in":    ttl,
			"scope":         DefaultScope,
			"refresh_token": nextRefresh,
		})
		return
	}
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	verifier := r.FormValue("code_verifier")
	resource := r.FormValue("resource")
	tok, ttl, err := h.S.ExchangeCode(code, redirectURI, clientID, verifier, resource)
	if err != nil {
		logging.L().Info("oauth token",
			"component", "oauth", "client_id", clientID,
			"auth_method", authMethod, "error", err.Error())
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}
	logging.L().Info("oauth token",
		"component", "oauth", "client_id", clientID,
		"auth_method", authMethod, "ok", true)
	refreshToken, err := h.S.RefreshForAccessToken(tok, DefaultScope)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "device authorization expired or revoked")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  tok,
		"token_type":    "Bearer",
		"expires_in":    ttl,
		"scope":         DefaultScope,
		"refresh_token": refreshToken,
	})
}

func (h *Handler) clientAuth(r *http.Request) (clientID, clientSecret, method string) {
	clientID = r.FormValue("client_id")
	clientSecret = r.FormValue("client_secret")
	if clientSecret != "" {
		return clientID, clientSecret, "client_secret_post"
	}
	authz := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(authz), "basic ") {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(authz[6:]))
		if err == nil {
			parts := strings.SplitN(string(raw), ":", 2)
			if len(parts) == 2 {
				id, _ := url.QueryUnescape(parts[0])
				sec, _ := url.QueryUnescape(parts[1])
				return id, sec, "client_secret_basic"
			}
		}
	}
	if clientID != "" {
		return clientID, "", "none"
	}
	return "", "", ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": desc,
	})
}

type authorizePageData struct {
	ClientName          string
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
	Resource            string
	DisplayResource     string
	Scope               string
	FormAction          string
}

var authorizePageTemplate = template.Must(template.New("authorize").Parse(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>授权访问 SubDesk</title>
<style>
:root{color-scheme:light;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f4f7fb;color:#172033}
*{box-sizing:border-box}body{margin:0;min-height:100vh;padding:32px 16px;display:grid;place-items:center;background:radial-gradient(circle at top,#e8f0ff 0,#f4f7fb 42%)}
.card{width:min(100%,620px);overflow:hidden;border:1px solid #dce4f0;border-radius:20px;background:#fff;box-shadow:0 18px 50px rgba(35,55,90,.12)}
header{padding:28px 32px 22px;background:#172554;color:#fff}header p{margin:8px 0 0;color:#dbeafe}h1{margin:0;font-size:1.65rem}.content{padding:28px 32px}
.request{margin:0 0 22px}.details{display:grid;gap:12px;margin:20px 0;padding:18px;border-radius:14px;background:#f7f9fc}.row{display:grid;grid-template-columns:92px 1fr;gap:12px}.key{color:#64748b}.value{font-weight:600;overflow-wrap:anywhere}
.notice{margin:20px 0;padding:14px 16px;border-left:4px solid #d97706;border-radius:8px;background:#fff7ed;color:#7c2d12}.notice strong{display:block;margin-bottom:4px}
label{display:block;margin:20px 0 8px;font-weight:700}input[type=password]{width:100%;padding:13px 14px;border:1px solid #94a3b8;border-radius:10px;font:inherit}input[type=password]:focus{outline:3px solid #bfdbfe;border-color:#2563eb}
.hint{margin:8px 0 0;color:#64748b;font-size:.9rem}button{width:100%;margin-top:22px;padding:13px 18px;border:0;border-radius:10px;background:#2563eb;color:#fff;font:inherit;font-weight:700;cursor:pointer}button:hover{background:#1d4ed8}
footer{padding:0 32px 28px;color:#64748b;font-size:.85rem}@media(max-width:560px){body{padding:0;background:#fff}.card{min-height:100vh;border:0;border-radius:0;box-shadow:none}header,.content,footer{padding-left:20px;padding-right:20px}.row{grid-template-columns:1fr;gap:3px}}
</style>
</head>
<body>
<main class="card">
<header><h1>授权访问 SubDesk</h1><p>请确认本次设备访问请求</p></header>
<section class="content">
<p class="request">客户端 <strong>{{.ClientName}}</strong> 正在请求访问此 Runtime。</p>
<div class="details" aria-label="授权详情">
<div class="row"><span class="key">客户端</span><span class="value">{{.ClientName}}<br><small>{{.ClientID}}</small></span></div>
<div class="row"><span class="key">资源</span><span class="value">{{if .DisplayResource}}{{.DisplayResource}}{{else}}由客户端在令牌请求中指定{{end}}</span></div>
<div class="row"><span class="key">权限</span><span class="value">{{.Scope}}</span></div>
<div class="row"><span class="key">授权后返回</span><span class="value">{{.RedirectURI}}</span></div>
</div>
<div class="notice"><strong>仅输入设备访问口令</strong>不要输入平台登录密码，也不要输入 Device Token。普通 HTTPS 中转并非端到端加密，中转服务可能接触提交内容；请只在你信任的设备入口继续。</div>
<form method="POST" action="{{.FormAction}}">
<label for="password">固定访问密码或临时访问码</label>
<input id="password" name="password" type="password" required autocomplete="current-password"/>
<p class="hint">请使用目标电脑客户端中设置的固定密码或临时码。临时码只能授权一次，访问在生成后十分钟内有效；刷新或撤销临时码会使原临时授权失效。不要输入平台账号密码或令牌。</p>
<input type="hidden" name="client_id" value="{{.ClientID}}"/>
<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}"/>
<input type="hidden" name="code_challenge" value="{{.CodeChallenge}}"/>
<input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}"/>
<input type="hidden" name="state" value="{{.State}}"/>
<input type="hidden" name="resource" value="{{.Resource}}"/>
<input type="hidden" name="scope" value="{{.Scope}}"/>
<button type="submit">确认并授权</button>
</form>
</section>
<footer>继续即表示你允许上述客户端按所列权限访问该资源。SubDesk 使用独立的 MCPX Runtime 执行本机授权。</footer>
</main>
</body>
</html>
`))
