package server

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"mcpx/internal/accesspolicy"
	"mcpx/internal/filescope"
)

const fileScopeEndpoint = "/local/filesystem-scope"

func (r *Runtime) fileScopeHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != fileScopeEndpoint {
			next.ServeHTTP(w, req)
			return
		}
		if !filescope.Available() {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		peer, _, e := net.SplitHostPort(req.RemoteAddr)
		ip := net.ParseIP(peer)
		if e != nil || ip == nil || !ip.IsLoopback() || req.Header.Get("Origin") != "" || req.Header.Get("Forwarded") != "" {
			http.Error(w, "local access only", 403)
			return
		}
		host := req.Host
		if parsed, _, err := net.SplitHostPort(host); err == nil {
			host = parsed
		}
		hostIP := net.ParseIP(strings.Trim(host, "[]"))
		if hostIP == nil || !hostIP.IsLoopback() || req.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "local host required", 403)
			return
		}
		for key := range req.Header {
			if strings.HasPrefix(strings.ToLower(key), "x-forwarded-") {
				http.Error(w, "local access only", 403)
				return
			}
		}
		token, e := accesspolicy.ReadPrivate(filescope.TokenPath(r.fileScopeStore().Home))
		got := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		if e != nil || len(token) != 64 || !strings.HasPrefix(req.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare(token, []byte(got)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		if req.Method != http.MethodGet && req.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		r.fileScopeMu.Lock()
		defer r.fileScopeMu.Unlock()
		policy, e := r.fileScopeStore().Load()
		if e != nil {
			http.Error(w, "scope state invalid; no fallback", 503)
			return
		}
		if req.Method == http.MethodPost {
			var input struct {
				Mode           string               `json:"mode"`
				ExpectedDigest string               `json:"expected_digest"`
				Roots          []filescope.RootSpec `json:"roots"`
				Confirm        bool                 `json:"confirm"`
			}
			dec := json.NewDecoder(http.MaxBytesReader(w, req.Body, 32768))
			dec.DisallowUnknownFields()
			if dec.Decode(&input) != nil {
				http.Error(w, "invalid request", 400)
				return
			}
			var extra any
			if dec.Decode(&extra) != io.EOF || !input.Confirm || input.ExpectedDigest != policy.Digest() {
				http.Error(w, "scope changed; refresh before saving", 409)
				return
			}
			if r.fileScopeActive != 0 || r.tasks.ActiveCount() != 0 {
				http.Error(w, "active requests or tasks; wait before changing scope", 409)
				return
			}
			for _, root := range input.Roots {
				ws, ok := r.reg.Get(root.Name)
				if !ok || ws.Path != root.Path {
					http.Error(w, "folder list changed; restart and refresh", 409)
					return
				}
			}
			policy, e = r.fileScopeStore().Save(input.Mode, input.Roots)
			if e != nil {
				http.Error(w, "scope could not be saved; refresh and inspect locally", 400)
				return
			}
		}
		roots := []map[string]string{}
		for _, root := range policy.Roots {
			roots = append(roots, map[string]string{"name": root.Name, "path": root.Path})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "scope_version": 1, "mode": policy.Mode, "file_only": policy.Mode == filescope.Folders, "runtime_enforced": true, "available": filescope.Available(), "digest": policy.Digest(), "roots": roots, "active_requests": r.fileScopeActive, "active_tasks": r.tasks.ActiveCount()})
	})
}
func (r *Runtime) beginScopeResource() (func(), error) {
	r.fileScopeMu.Lock()
	defer r.fileScopeMu.Unlock()
	if e := r.checkFileScopeResource(); e != nil {
		return nil, e
	}
	r.fileScopeActive++
	return func() { r.fileScopeMu.Lock(); r.fileScopeActive--; r.fileScopeMu.Unlock() }, nil
}
