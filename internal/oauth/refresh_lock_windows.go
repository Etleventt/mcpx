//go:build windows

package oauth

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// The .lock file is stable while the JSON snapshot is atomically replaced.
func withRefreshProcessLock(path string, run func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	handle, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer handle.Close()
	var overlapped windows.Overlapped
	h := windows.Handle(handle.Fd())
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped); err != nil {
		return fmt.Errorf("lock OAuth refresh grants: %w", err)
	}
	defer windows.UnlockFileEx(h, 0, 1, 0, &overlapped)
	return run()
}
