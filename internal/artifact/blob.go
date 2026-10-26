package artifact

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"mcpx/internal/config"
)

const (
	MaxBlobSize          = 8 << 20
	MaxStoredScreenshots = config.AutoScreenshotMaxRows
	ScreenshotRetention  = config.AutoScreenshotRetention
)

// RegisterBytes stores a bounded immutable artifact without writing into the workspace.
func (s *Service) RegisterBytes(ctx context.Context, sessionID, principalID, name, kind, mimeType string, content []byte) (Artifact, error) {
	if len(content) == 0 || len(content) > MaxBlobSize {
		return Artifact{}, fmt.Errorf("artifact blob size out of range")
	}
	sum := sha256.Sum256(content)
	now := s.now().UTC()
	item := Artifact{ID: randomID(), RemoteSessionID: sessionID, Name: name,
		Kind: kind, Path: "", MIMEType: mimeType, Size: int64(len(content)),
		SHA256: "sha256:" + hex.EncodeToString(sum[:]), CreatedAt: now}
	item.ResourceURI = ResourceURI(sessionID, item.ID)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Artifact{}, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO artifacts
		(id, remote_session_id, name, kind, path, mime_type, size, sha256, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID, item.RemoteSessionID, item.Name, item.Kind, item.Path,
		item.MIMEType, item.Size, item.SHA256, principalID, now.UnixMilli())
	if err != nil {
		return Artifact{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO artifact_blobs(artifact_id, content) VALUES(?, ?)`, item.ID, content); err != nil {
		return Artifact{}, err
	}
	// Screenshot data can contain private desktop information. Keep a bounded
	// recovery window even when the optional background retention is disabled.
	// Foreign-key cascading also removes the corresponding blob.
	if kind == "screenshot" {
		if err = pruneScreenshots(ctx, tx, now); err != nil {
			return Artifact{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return Artifact{}, err
	}
	return item, nil
}

func pruneScreenshots(ctx context.Context, tx *sql.Tx, now time.Time) error {
	// Explicit plan evidence remains durable; only unattached recovery copies
	// are eligible for TTL/count eviction.
	_, err := tx.ExecContext(ctx, `DELETE FROM artifacts WHERE id IN (
		SELECT a.id FROM artifacts a
		WHERE a.kind = 'screenshot' AND a.path = '' AND a.created_at < ?
		  AND NOT EXISTS (SELECT 1 FROM plan_task_evidence e
		                  WHERE e.kind = 'artifact' AND e.reference_id = a.id)
	)`, now.Add(-ScreenshotRetention).UnixMilli())
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM artifacts WHERE id IN (
		SELECT a.id FROM artifacts a
		WHERE a.kind = 'screenshot' AND a.path = ''
		  AND NOT EXISTS (SELECT 1 FROM plan_task_evidence e
		                  WHERE e.kind = 'artifact' AND e.reference_id = a.id)
		ORDER BY a.created_at DESC, a.id DESC
		LIMIT -1 OFFSET ?
	)`, MaxStoredScreenshots)
	return err
}

func (s *Service) blobContent(ctx context.Context, artifactID string) ([]byte, bool, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx, `SELECT content FROM artifact_blobs WHERE artifact_id = ?`, artifactID).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func (s *Service) readBlob(ctx context.Context, item Artifact, offset int64, limit int) (ReadResult, error) {
	data, ok, err := s.blobContent(ctx, item.ID)
	if err != nil {
		return ReadResult{}, fmt.Errorf("artifact blob unavailable: %w", err)
	}
	if !ok {
		return ReadResult{}, ErrNotFound
	}
	digest := sha256.Sum256(data)
	if int64(len(data)) != item.Size || "sha256:"+hex.EncodeToString(digest[:]) != item.SHA256 {
		return ReadResult{}, ErrChanged
	}
	if offset < 0 {
		offset = 0
	}
	if offset > int64(len(data)) {
		offset = int64(len(data))
	}
	if limit <= 0 || limit > 1<<20 {
		limit = 256 << 10
	}
	end := offset + int64(limit)
	if end > int64(len(data)) {
		end = int64(len(data))
	}
	chunk := data[offset:end]
	return ReadResult{Artifact: item, Offset: offset, Next: end, EOF: end >= int64(len(data)),
		Encoding: "base64", Data: base64.StdEncoding.EncodeToString(chunk)}, nil
}
