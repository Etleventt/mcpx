package config

import (
	"fmt"
	"strings"
)

// ValidateDefaultApprovalMode validates the process-wide default used when a
// client opens a Remote Session without specifying approval_mode.
func ValidateDefaultApprovalMode(mode string) error {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "standard", "trusted":
		return nil
	default:
		return fmt.Errorf("remote_sessions.default_approval_mode must be standard|trusted")
	}
}

// DefaultApprovalMode returns a normalized safe default.
func DefaultApprovalMode(c RemoteSessionsConfig) string {
	mode := strings.ToLower(strings.TrimSpace(c.DefaultApprovalMode))
	if mode == "trusted" {
		return "trusted"
	}
	return "standard"
}
