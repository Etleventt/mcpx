package server

import (
	"context"
	"testing"

	"mcpx/internal/mcpresult"
	"mcpx/internal/remotesession"
)

func TestScreenshotReturnsImageWhenArtifactDatabaseIsUnavailable(t *testing.T) {
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
	if _, err := rt.state.DB().Exec("DROP TABLE artifact_blobs"); err != nil {
		t.Fatal(err)
	}
	result, err := rt.toolScreenshotCapture(context.Background(), mcpresult.Request(map[string]any{
		"intent": "capture", "remote_session_id": created.Session.ID, "mode": "fullscreen",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !statusOK(decodeToolResult(t, result)) || len(result.Content) < 2 {
		t.Fatalf("screenshot failed after successful capture: %+v", result)
	}
	data := structuredBusinessData(result)
	if data["persistence_warning"] == nil || data["artifact_id"] != nil || data["resource_uri"] != nil {
		t.Fatalf("screenshot persistence failure not distinguished: %+v", data)
	}
}
