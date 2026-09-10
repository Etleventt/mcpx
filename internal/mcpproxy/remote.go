package mcpproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcpx/internal/config"
)

type remoteRequestConfig struct {
	endpoint string
	origin   string
	headers  http.Header
	query    url.Values
}

type credentialRoundTripper struct {
	base    http.RoundTripper
	origin  string
	headers http.Header
	query   url.Values
}

func remoteTransportType(srv config.MCPServer) (string, error) {
	typeName := strings.ToLower(strings.TrimSpace(srv.Type))
	if typeName == "" {
		if strings.TrimSpace(srv.URL) != "" {
			return "streamable-http", nil
		}
		return "", nil
	}
	switch typeName {
	case "stdio":
		return "", nil
	case "http", "streamable-http", "streamable_http":
		if strings.TrimSpace(srv.URL) == "" {
			return "", errors.New("remote MCP url is required")
		}
		return "streamable-http", nil
	case "sse":
		if strings.TrimSpace(srv.URL) == "" {
			return "", errors.New("remote MCP url is required")
		}
		return "sse", nil
	default:
		return "", fmt.Errorf("unsupported MCP transport type %q", srv.Type)
	}
}

func connectRemote(ctx context.Context, client *mcp.Client, srv config.MCPServer, transportType string) (*mcp.ClientSession, error) {
	cfg, err := buildRemoteRequestConfig(srv)
	if err != nil {
		return nil, err
	}
	base := http.DefaultTransport
	roundTripper := &credentialRoundTripper{base: base, origin: cfg.origin, headers: cfg.headers, query: cfg.query}
	httpClient := &http.Client{Transport: roundTripper}
	if len(cfg.headers) > 0 || len(cfg.query) > 0 {
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("remote MCP redirect limit exceeded")
			}
			if requestOrigin(req.URL) != cfg.origin {
				return errors.New("remote MCP credentialed redirect crossed origin")
			}
			return nil
		}
	}
	switch transportType {
	case "streamable-http":
		return client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: cfg.endpoint, HTTPClient: httpClient}, nil)
	case "sse":
		return client.Connect(ctx, &mcp.SSEClientTransport{Endpoint: cfg.endpoint, HTTPClient: httpClient}, nil)
	default:
		return nil, fmt.Errorf("unsupported remote MCP transport %q", transportType)
	}
}

func buildRemoteRequestConfig(srv config.MCPServer) (remoteRequestConfig, error) {
	parsed, err := url.Parse(strings.TrimSpace(srv.URL))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return remoteRequestConfig{}, errors.New("remote MCP url must be an absolute HTTP(S) URL")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return remoteRequestConfig{}, errors.New("remote MCP url cannot contain userinfo or fragment")
	}
	if parsed.Scheme == "http" && !srv.AllowInsecureHTTP && !loopbackHost(parsed.Hostname()) {
		return remoteRequestConfig{}, errors.New("remote MCP requires HTTPS unless allow_insecure_http is explicitly enabled")
	}
	query := parsed.Query()
	for name, values := range query {
		for index, value := range values {
			expanded, expandErr := expandCredential(value)
			if expandErr != nil {
				return remoteRequestConfig{}, expandErr
			}
			if err := validateQueryCredential(name, expanded); err != nil {
				return remoteRequestConfig{}, err
			}
			values[index] = expanded
		}
		query[name] = values
	}
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	origin := requestOrigin(parsed)
	headers := make(http.Header)
	for name, raw := range srv.Headers {
		value, expandErr := expandCredential(raw)
		if expandErr != nil {
			return remoteRequestConfig{}, expandErr
		}
		if err := validateCredentialHeader(name, value); err != nil {
			return remoteRequestConfig{}, err
		}
		headers.Set(name, value)
	}
	for name, raw := range srv.Query {
		value, expandErr := expandCredential(raw)
		if expandErr != nil {
			return remoteRequestConfig{}, expandErr
		}
		if err := validateQueryCredential(name, value); err != nil {
			return remoteRequestConfig{}, err
		}
		query.Set(name, value)
	}
	if srv.Auth != nil {
		if err := applyStructuredAuth(headers, query, *srv.Auth); err != nil {
			return remoteRequestConfig{}, err
		}
	}
	return remoteRequestConfig{endpoint: parsed.String(), origin: origin, headers: headers, query: query}, nil
}

func applyStructuredAuth(headers http.Header, query url.Values, auth config.MCPAuthConfig) error {
	typeName := strings.ToLower(strings.TrimSpace(auth.Type))
	switch typeName {
	case "", "none":
		return nil
	case "bearer", "token":
		token, expandErr := expandCredential(auth.Token)
		if expandErr != nil {
			return expandErr
		}
		token = strings.TrimSpace(token)
		if token == "" {
			return errors.New("bearer authentication requires a token")
		}
		if headers.Get("Authorization") != "" {
			return errors.New("bearer authentication conflicts with configured Authorization header")
		}
		headers.Set("Authorization", "Bearer "+token)
		return nil
	case "api_key", "api-key", "apikey":
		token, expandErr := expandCredential(auth.Token)
		if expandErr != nil {
			return expandErr
		}
		if strings.TrimSpace(token) == "" {
			return errors.New("API key authentication requires a token")
		}
		location := strings.ToLower(strings.TrimSpace(auth.In))
		if location == "" {
			location = "header"
		}
		switch location {
		case "header":
			name := strings.TrimSpace(auth.Name)
			if name == "" {
				name = "X-API-Key"
			}
			if err := validateCredentialHeader(name, token); err != nil {
				return err
			}
			if headers.Get(name) != "" {
				return fmt.Errorf("API key authentication conflicts with configured header %q", name)
			}
			headers.Set(name, token)
			return nil
		case "query", "query_param", "query-param":
			name := strings.TrimSpace(auth.Name)
			if name == "" {
				name = "api_key"
			}
			if err := validateQueryCredential(name, token); err != nil {
				return err
			}
			if query.Has(name) {
				return fmt.Errorf("API key authentication conflicts with configured query parameter %q", name)
			}
			query.Set(name, token)
			return nil
		default:
			return fmt.Errorf("unsupported API key location %q", auth.In)
		}
	default:
		return fmt.Errorf("unsupported MCP authentication type %q", auth.Type)
	}
}

func (t *credentialRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	if requestOrigin(req.URL) != t.origin {
		return base.RoundTrip(req)
	}
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	copyURL := *req.URL
	clone.URL = &copyURL
	for name, values := range t.headers {
		clone.Header.Del(name)
		for _, value := range values {
			clone.Header.Add(name, value)
		}
	}
	if len(t.query) > 0 {
		query := clone.URL.Query()
		for name, values := range t.query {
			query.Del(name)
			for _, value := range values {
				query.Add(name, value)
			}
		}
		clone.URL.RawQuery = query.Encode()
	}
	return base.RoundTrip(clone)
}

func requestOrigin(value *url.URL) string {
	if value == nil {
		return ""
	}
	return strings.ToLower(value.Scheme) + "://" + strings.ToLower(value.Host)
}

func loopbackHost(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func expandCredential(raw string) (string, error) {
	missing := ""
	value := os.Expand(raw, func(name string) string {
		resolved, ok := os.LookupEnv(name)
		if !ok && missing == "" {
			missing = name
		}
		return resolved
	})
	if missing != "" {
		return "", fmt.Errorf("remote MCP credential environment variable %q is not set", missing)
	}
	return value, nil
}

func validateCredentialHeader(name, value string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 || !validHeaderName(name) {
		return fmt.Errorf("invalid remote MCP header name %q", name)
	}
	if strings.ContainsAny(value, "\r\n") || len(value) > 16<<10 {
		return fmt.Errorf("invalid value for remote MCP header %q", name)
	}
	return nil
}

func validHeaderName(name string) bool {
	for _, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", char) {
			continue
		}
		return false
	}
	return true
}

func validateQueryCredential(name, value string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 256 || strings.ContainsAny(name+value, "\r\n") || len(value) > 16<<10 {
		return errors.New("invalid remote MCP query credential")
	}
	return nil
}

func redactMCPError(srv config.MCPServer, err error) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	values := credentialValues(srv)
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	for _, value := range values {
		if len(value) < 4 {
			continue
		}
		message = strings.ReplaceAll(message, value, "[redacted]")
		message = strings.ReplaceAll(message, url.QueryEscape(value), "[redacted]")
	}
	return errors.New(message)
}

func credentialValues(srv config.MCPServer) []string {
	values := []string{}
	for _, raw := range srv.Headers {
		value := os.ExpandEnv(raw)
		values = append(values, value)
		if parts := strings.SplitN(value, " ", 2); len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			values = append(values, parts[1])
		}
	}
	for _, raw := range srv.Query {
		values = append(values, os.ExpandEnv(raw))
	}
	if parsed, err := url.Parse(strings.TrimSpace(srv.URL)); err == nil {
		for _, parts := range parsed.Query() {
			for _, value := range parts {
				values = append(values, os.ExpandEnv(value))
			}
		}
	}
	if srv.Auth != nil {
		values = append(values, os.ExpandEnv(srv.Auth.Token))
	}
	return values
}

func DescribeTarget(srv config.MCPServer) string {
	if strings.TrimSpace(srv.URL) == "" {
		return DescribeCommand(srv)
	}
	parsed, err := url.Parse(strings.TrimSpace(srv.URL))
	if err != nil || parsed.Host == "" {
		return "remote-mcp"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func AuthenticationDescriptor(srv config.MCPServer) map[string]any {
	locations := []string{}
	mode := "none"
	if srv.Auth != nil && strings.TrimSpace(srv.Auth.Type) != "" {
		mode = strings.ToLower(strings.TrimSpace(srv.Auth.Type))
	}
	for name := range srv.Headers {
		if strings.EqualFold(name, "Authorization") {
			if mode == "none" {
				mode = "bearer_or_authorization_header"
			}
		} else {
			locations = append(locations, "header")
			if mode == "none" {
				mode = "custom_header"
			}
		}
	}
	if len(srv.Query) > 0 {
		locations = append(locations, "query")
		if mode == "none" {
			mode = "query_api_key_or_custom"
		}
	}
	if parsed, err := url.Parse(strings.TrimSpace(srv.URL)); err == nil && parsed.RawQuery != "" {
		locations = append(locations, "query")
		if mode == "none" {
			mode = "query_api_key_or_custom"
		}
	}
	if srv.Auth != nil && strings.Contains(strings.ToLower(srv.Auth.In), "query") {
		locations = append(locations, "query")
	} else if srv.Auth != nil && mode == "api_key" {
		locations = append(locations, "header")
	}
	locations = uniqueSorted(locations)
	return map[string]any{"mode": mode, "credential_locations": locations, "secrets_exposed": false}
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
