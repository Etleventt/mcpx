package server

import (
	"context"
	"testing"

	"mcpx/internal/envelope"
	"mcpx/internal/remotesession"
)

func TestNewRemoteSessionInheritsGlobalApprovalMode(t *testing.T) {
	runtime := newWorkspaceRuntime(t, "demo")
	runtime.cfg.RemoteSessions.DefaultApprovalMode = remotesession.ApprovalModeTrusted
	principal, err := runtime.principalFromContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	created, err := runtime.createRemoteSession(context.Background(), principal, envelope.Request{Payload: map[string]any{}}, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if created.Session.ApprovalMode != remotesession.ApprovalModeTrusted {
		t.Fatalf("inherited approval mode=%q", created.Session.ApprovalMode)
	}

	explicit, err := runtime.createRemoteSession(context.Background(), principal, envelope.Request{Payload: map[string]any{
		"approval_mode": remotesession.ApprovalModeStandard,
	}}, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if explicit.Session.ApprovalMode != remotesession.ApprovalModeStandard {
		t.Fatalf("explicit approval mode=%q", explicit.Session.ApprovalMode)
	}
}
