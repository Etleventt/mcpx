//go:build !windows

package oauth

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Lock a separate, stable file so atomic renames of the JSON snapshot do not
// invalidate the lock across overlapping Runtime processes.
func withRefreshProcessLock(path string, run func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	handle, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer handle.Close()
	if err := unix.Flock(int(handle.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock OAuth refresh grants: %w", err)
	}
	defer unix.Flock(int(handle.Fd()), unix.LOCK_UN)
	return run()
}
