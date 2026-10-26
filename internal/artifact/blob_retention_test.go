package artifact

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"mcpx/internal/auth"
	"mcpx/internal/remotesession"
	"mcpx/internal/state"
)

func TestScreenshotBlobsAreBoundedAndExpired(t *testing.T) {
	ctx := context.Background()
	workspace := t.TempDir()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	principal := auth.Principal{ID: "p", Kind: "test", SubjectHash: "owner"}
	session, err := remotesession.NewService(store.DB()).Create(ctx, principal,
		remotesession.CreateInput{WorkspaceName: "demo", WorkspacePath: workspace})
	if err != nil {
		t.Fatal(err)
	}
	id := session.Session.ID
	service := NewService(store.DB())
	start := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	first := ""
	for i := 0; i < MaxStoredScreenshots+1; i++ {
		j := i
		service.now = func() time.Time { return start.Add(time.Duration(j) * time.Millisecond) }
		item, err := service.RegisterBytes(ctx, id, principal.ID, "Screenshot", "screenshot", "image/png",
			[]byte{0x89, 0x50, 0x4e, 0x47, byte(j)})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = item.ID
		}
	}
	var stored, orphanBlobs int
	if err := store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM artifacts WHERE kind = 'screenshot' AND path = ''`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != MaxStoredScreenshots {
		t.Fatalf("stored %d, want %d", stored, MaxStoredScreenshots)
	}
	if _, err := service.Get(ctx, id, first); !errors.Is(err, ErrNotFound) {
		t.Fatalf("oldest screenshot not evicted: %v", err)
	}
	if err := store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM artifact_blobs b
		LEFT JOIN artifacts a ON a.id = b.artifact_id WHERE a.id IS NULL`).Scan(&orphanBlobs); err != nil {
		t.Fatal(err)
	}
	if orphanBlobs != 0 {
		t.Fatalf("orphan blobs after cleanup: %d", orphanBlobs)
	}

	service.now = func() time.Time { return start.Add(ScreenshotRetention + time.Hour) }
	content := []byte{0x89, 0x50, 0x4e, 0x47, 7}
	item, err := service.RegisterBytes(ctx, id, principal.ID, "Screenshot", "screenshot", "image/png", content)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM artifacts WHERE kind = 'screenshot' AND path = ''`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 1 {
		t.Fatalf("expired screenshots retained: %d", stored)
	}
	page, err := service.Read(ctx, id, item.ID, workspace, 0, 32)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(page.Data)
	if err != nil || !bytes.Equal(decoded, content) {
		t.Fatalf("recovered screenshot differs: %v %x", err, decoded)
	}
	if _, err = store.DB().ExecContext(ctx, `UPDATE artifact_blobs SET content = ? WHERE artifact_id = ?`,
		[]byte{9, 9, 9}, item.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Read(ctx, id, item.ID, workspace, 0, 32); !errors.Is(err, ErrChanged) {
		t.Fatalf("corrupted screenshot read accepted: %v", err)
	}
}
