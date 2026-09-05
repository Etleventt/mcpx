package server

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"mcpx/internal/changeset"
)

func TestDiffPagesReconstructCompleteUnicodeContent(t *testing.T) {
	item := changeset.Changeset{ID: "chg_page", RemoteSessionID: "session_page", Digest: "sha256:page", UnifiedDiff: strings.Repeat("+中文🙂\n", 100)}
	var restored strings.Builder
	for offset := 0; offset < len(item.UnifiedDiff); {
		data, err := changeDiffPageData(item, offset, 13)
		if err != nil {
			t.Fatal(err)
		}
		page := data["diff"].(map[string]any)
		text := page["content"].(string)
		if len(text) > 13 || !utf8.ValidString(text) || data["digest"] != item.Digest || data["expected_digest"] != item.Digest {
			t.Fatalf("invalid page: %+v", data)
		}
		next := page["next_offset"].(int)
		if next <= offset {
			t.Fatal("paging stalled")
		}
		restored.WriteString(text)
		offset = next
		if offset < len(item.UnifiedDiff) && data["next_action"] == nil {
			t.Fatal("continuation missing")
		}
	}
	if restored.String() != item.UnifiedDiff {
		t.Fatal("paging lost content")
	}
	if _, err := changeDiffPageData(item, -1, 10); err == nil {
		t.Fatal("negative offset accepted")
	}
	if _, err := changeDiffPageData(item, 2, 10); err == nil {
		t.Fatal("mid-rune offset accepted")
	}
	if _, err := changeDiffPageData(item, len(item.UnifiedDiff)+1, 10); err == nil {
		t.Fatal("oversized offset accepted")
	}
}

func TestDiffPagingThroughPublicTool(t *testing.T) {
	rt := newWorkspaceRuntime(t, "demo")
	workspace, _ := rt.reg.Get("demo")
	session := operationTestSession(t, rt, "demo")
	principal, err := rt.principalFromContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := rt.changesets.Prepare(context.Background(), session.ID, principal.ID, workspace.Path, "diff fixture", []changeset.Operation{{Operation: "create", Path: "fixture.txt", Content: strings.Repeat("中文\n", 50)}})
	if err != nil {
		t.Fatal(err)
	}
	result := callOperationTool(t, rt, "change_read", map[string]any{"session_id": session.ID, "view": "diff", "changeset_id": prepared.ID, "offset": 0, "limit": 64})
	if result["status"] != "succeeded" {
		t.Fatalf("read failed: %+v", result)
	}
	data := result["data"].(map[string]any)
	page := data["diff"].(map[string]any)
	if page["mode"] != "page" || data["digest"] != prepared.Digest || page["truncated"] != true {
		t.Fatalf("public paging mismatch: %+v", data)
	}
}
