package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"mcpx/internal/changeset"
)

func TestSourcePublicViewsHonorPaths(t *testing.T) {
	rt := newWorkspaceRuntime(t, "demo")
	workspace, _ := rt.reg.Get("demo")
	for _, path := range []string{"wanted/a.go", "wanted/b.go", "unrelated/c.go"} {
		absolute := filepath.Join(workspace.Path, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(absolute, []byte("needle\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	session := operationTestSession(t, rt, "demo")
	for _, view := range []string{"list", "search", "context"} {
		response := callOperationTool(t, rt, "source_read", map[string]any{
			"session_id": session.ID, "view": view, "paths": []any{"wanted"}, "query": "needle", "limit": 1,
		})
		if response["status"] != "succeeded" {
			t.Fatalf("%s failed: %+v", view, response)
		}
		data := response["data"].(map[string]any)
		key := "files"
		if view == "search" {
			key = "matches"
		}
		items := data[key].([]any)
		if len(items) == 0 {
			t.Fatalf("%s empty: %+v", view, data)
		}
		for _, raw := range items {
			path := raw.(map[string]any)["path"].(string)
			if !strings.HasPrefix(path, "wanted/") {
				t.Fatalf("%s leaked %s", view, path)
			}
		}
		if next, ok := data["next_action"].(map[string]any); ok {
			args := next["arguments"].(map[string]any)
			paths, ok := args["paths"].([]any)
			if !ok || len(paths) != 1 || paths[0] != "wanted" {
				t.Fatalf("scope lost in continuation: %+v", args)
			}
		}
	}
}

func TestChangeResultBoundsLongLinesAndPreservesIdentifiers(t *testing.T) {
	f := changeset.FileChange{Operation: "update", Path: "large.txt", Original: []byte(strings.Repeat("旧", 100000)), Proposed: []byte(strings.Repeat("新", 100000))}
	item := changeset.Changeset{ID: "chg_fixture", RemoteSessionID: "session_fixture", Digest: "sha256:fixture", Files: []changeset.FileChange{f}, UnifiedDiff: changeset.UnifiedDiffForFile(f)}
	dto := changeSummaryDTO(item)
	diff := dto["diff"].(map[string]any)
	preview := diff["unified_diff_preview"].(string)
	if len(preview) > diffInlineMaxBytes || !utf8.ValidString(preview) || diff["mode"] != "resource" {
		t.Fatalf("unbounded or invalid diff preview: bytes=%d", len(preview))
	}
	encoded, err := json.Marshal(dto)
	if err != nil || len(encoded) > 48<<10 {
		t.Fatalf("response bytes=%d err=%v", len(encoded), err)
	}
	if dto["digest"] != item.Digest || dto["expected_digest"] != item.Digest || diff["resource_uri"] == "" {
		t.Fatal("compact result lost revision or recovery identifiers")
	}
}
