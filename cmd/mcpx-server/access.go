package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"gopkg.in/yaml.v3"
	"io"
	"mcpx/internal/accesspolicy"
	"mcpx/internal/config"
	"path/filepath"
	"strings"
)

func runAccess(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	result, err := localAccess(args, stdin)
	if err != nil {
		_ = json.NewEncoder(stderr).Encode(map[string]any{"ok": false, "error": err.Error()})
		return 1
	}
	if json.NewEncoder(stdout).Encode(result) != nil {
		return 1
	}
	return 0
}
func localAccess(args []string, stdin io.Reader) (map[string]any, error) {
	bad := errors.New("invalid access operation; fixed set requires password JSON on stdin")
	action := strings.Join(args, " ")
	switch action {
	case "status", "temporary create", "temporary generate --ttl 10m", "temporary revoke", "fixed set --password-stdin", "fixed generate", "token generate", "token revoke":
	default:
		return nil, bad
	}
	home, err := config.HomeDir()
	if err != nil || accesspolicy.CheckHome(home) != nil {
		return nil, accesspolicy.ErrState
	}
	raw, err := accesspolicy.ReadPrivate(filepath.Join(home, "config.yaml"))
	if err != nil {
		return nil, accesspolicy.ErrState
	}
	var cfg config.Config
	if yaml.Unmarshal(raw, &cfg) != nil || config.EffectiveAuthMode(cfg.Auth) != "oauth" || cfg.Auth.OAuth.Password == "" {
		return nil, errors.New("device access requires an existing protected OAuth-only Runtime configuration")
	}
	store := &accesspolicy.Store{Home: home, LegacyPassword: strings.TrimSpace(cfg.Auth.OAuth.Password)}
	result := map[string]any{"ok": true, "access_version": 2}
	var status accesspolicy.Status
	switch action {
	case "status":
		status, err = store.Status()
	case "temporary create", "temporary generate --ttl 10m":
		var value string
		status, value, err = store.CreateTemporary()
		if err == nil {
			result["temporary_code"] = value
		}
	case "temporary revoke":
		status, err = store.RevokeTemporary()
	case "fixed generate":
		var value string
		status, value, err = store.GenerateFixed()
		if err == nil {
			result["fixed_password"] = value
		}
	case "token generate":
		var value string
		status, value, err = store.GenerateMCPToken()
		if err == nil {
			result["mcp_token"] = value
		}
	case "token revoke":
		status, err = store.RevokeMCPToken()
	case "fixed set --password-stdin":
		input, e := io.ReadAll(io.LimitReader(stdin, 16385))
		if e != nil || len(input) > 16384 {
			return nil, bad
		}
		var q struct {
			Password string `json:"password"`
		}
		decoder := json.NewDecoder(bytes.NewReader(input))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&q) != nil {
			return nil, bad
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return nil, bad
		}
		status, err = store.SetFixed(q.Password)
	}
	if err != nil {
		return nil, err
	}
	result["access"] = status
	return result, nil
}
