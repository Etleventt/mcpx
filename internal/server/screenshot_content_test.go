package server

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcpx/internal/auth"
	"mcpx/internal/mcpresult"
	"mcpx/internal/remotesession"
	"mcpx/internal/screenshot"
)

func TestScreenshotResultIncludesImageContent(t *testing.T) {
	rt := newWorkspaceRuntime(t, "demo")
	principal, err := rt.principalFromContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	registered, _ := rt.reg.Get("demo")
	created, err := rt.remote.Create(context.Background(), principal, remotesession.CreateInput{
		WorkspaceName: "demo", WorkspacePath: registered.Path,
	})
	if err != nil {
		t.Fatal(err)
	}
	rt.screenshot = fakeScreenCapturer{}
	ctx := auth.ContextWithAuthorization(context.Background(), "Bearer developer-token")
	// open mode for newWorkspaceRuntime uses open auth - check
	res, err := rt.toolScreenshotCapture(ctx, mcpresult.Request(map[string]any{
		"intent": "capture", "remote_session_id": created.Session.ID, "mode": "fullscreen",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Content) < 2 {
		t.Fatalf("content len=%d sc=%+v", len(res.Content), res.StructuredContent)
	}
	resultData := structuredBusinessData(res)
	if resultData["mode"] == nil || resultData["artifact_id"] == nil || resultData["resource_uri"] == nil {
		t.Fatalf("screenshot metadata compatibility failure: %+v", resultData)
	}
	items, err := rt.artifacts.List(context.Background(), created.Session.ID, "screenshot", 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("screenshot artifact: %v %+v", err, items)
	}
	registeredArtifact, data, err := rt.artifacts.ReadAll(context.Background(), created.Session.ID, items[0].ID, registered.Path, 8<<20)
	if err != nil || len(data) == 0 || registeredArtifact.ResourceURI == "" {
		t.Fatalf("screenshot fallback unavailable: %v", err)
	}
	if _, _, err := rt.artifacts.ReadAll(context.Background(), "other-session", items[0].ID, registered.Path, 8<<20); err == nil {
		t.Fatal("screenshot artifact is visible across sessions")
	}
	resource, err := rt.resourceArtifact(context.Background(), &mcp.ReadResourceRequest{
		Params: &mcp.ReadResourceParams{URI: registeredArtifact.ResourceURI},
	})
	if err != nil || len(resource.Contents) != 1 || string(resource.Contents[0].Blob) != string(data) {
		t.Fatalf("screenshot resource not delivered as image blob: err=%v resource=%+v", err, resource)
	}
	_ = screenshot.Request{}
}
