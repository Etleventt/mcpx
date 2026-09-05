package server

import (
	"fmt"
	"unicode/utf8"

	"mcpx/internal/changeset"
)

func changeDiffPageAction(item changeset.Changeset, offset, limit int) map[string]any {
	return nextActionWithReason("change_read", "按字节分页读取完整差异；复制 next_offset 继续", map[string]any{
		"session_id": item.RemoteSessionID, "view": "diff", "changeset_id": item.ID,
		"offset": offset, "limit": limit,
	})
}

func changeDiffPageData(item changeset.Changeset, offset, limit int) (map[string]any, error) {
	text := item.UnifiedDiff
	if offset < 0 || offset > len(text) || limit < 0 {
		return nil, fmt.Errorf("invalid diff offset or limit")
	}
	if offset < len(text) && !utf8.RuneStart(text[offset]) {
		return nil, fmt.Errorf("diff offset must be on a UTF-8 boundary")
	}
	if limit == 0 {
		limit = diffInlineMaxBytes
	}
	limit = max(4, min(limit, 64<<10))
	end := offset + min(limit, len(text)-offset)
	for end > offset && end < len(text) && !utf8.RuneStart(text[end]) {
		end--
	}
	data := map[string]any{
		"changeset_id": item.ID, "remote_session_id": item.RemoteSessionID,
		"digest": item.Digest, "expected_digest": item.Digest, "status": item.Status,
		"diff": map[string]any{
			"mode": "page", "content": text[offset:end], "offset": offset,
			"next_offset": end, "bytes": len(text), "limit": limit, "truncated": end < len(text),
		},
	}
	if end < len(text) {
		data["next_action"] = changeDiffPageAction(item, end, limit)
	}
	return data, nil
}
