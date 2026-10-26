package oauth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type refreshDisk struct {
	Version int                      `json:"version"`
	Grants  map[string]*refreshGrant `json:"grants"`
}

func refreshID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func cloneRefresh(items map[string]*refreshGrant) map[string]*refreshGrant {
	clone := make(map[string]*refreshGrant, len(items))
	for k, v := range items {
		cp := *v
		clone[k] = &cp
	}
	return clone
}

// SetRefreshPersistPath restores grant-bound refresh tokens after restart.
// Only token hashes are stored on disk; no bearer refresh secret is written.
func (s *Server) SetRefreshPersistPath(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if path == "" {
		s.refreshPersistPath = ""
		return nil
	}
	return withRefreshProcessLock(path, func() error {
		restored, err := s.loadRefreshStore(path)
		if err != nil {
			return err
		}
		s.refresh = restored
		s.refreshPersistPath = path
		return nil
	})
}

// withRefreshStoreLocked serializes both refresh rotation and token issuance
// across overlapping Runtime processes using the same MCPX_HOME. s.mu is held.
func (s *Server) withRefreshStoreLocked(update func() error) error {
	if s.refreshPersistPath == "" {
		return update()
	}
	return withRefreshProcessLock(s.refreshPersistPath, func() error {
		restored, err := s.loadRefreshStore(s.refreshPersistPath)
		if err != nil {
			return err
		}
		s.refresh = restored
		return update()
	})
}

func (s *Server) loadRefreshStore(path string) (map[string]*refreshGrant, error) {
	restored := map[string]*refreshGrant{}
	handle, err := os.Open(path)
	if os.IsNotExist(err) {
		return restored, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read refresh grants: %w", err)
	}
	defer handle.Close()
	const maxRefreshFileBytes = 8 << 20
	raw, err := io.ReadAll(io.LimitReader(handle, maxRefreshFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read refresh grants: %w", err)
	}
	if len(raw) > maxRefreshFileBytes {
		return nil, fmt.Errorf("refresh grant store exceeds size limit")
	}
	var data refreshDisk
	if err := json.Unmarshal(raw, &data); err != nil || data.Version != 1 {
		return nil, fmt.Errorf("invalid refresh grant store")
	}
	if len(data.Grants) > MaxRefreshTokens {
		return nil, fmt.Errorf("refresh grant store exceeds token limit")
	}
	now := time.Now()
	for id, grant := range data.Grants {
		if len(id) != 64 || strings.Trim(id, "0123456789abcdef") != "" || grant == nil {
			return nil, fmt.Errorf("invalid refresh grant key")
		}
		// Access-policy validation is deliberately done on redemption, not
		// once per entry on every store read: it can acquire a device policy
		// lock and would otherwise turn refresh into O(n) disk reads.
		if now.Before(grant.ExpiresAt) {
			restored[id] = grant
		}
	}
	return restored, nil
}

// persistRefreshLocked publishes a complete snapshot atomically. Callers hold s.mu.
func (s *Server) persistRefreshLocked() error {
	if s.refreshPersistPath == "" {
		return nil
	}
	raw, err := json.Marshal(refreshDisk{Version: 1, Grants: s.refresh})
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.refreshPersistPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".oauth-refresh-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err = temp.Write(raw); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), s.refreshPersistPath)
}
