//go:build !windows

package accesspolicy

import (
	"golang.org/x/sys/unix"
	"os"
	"syscall"
)

func isReparse(string) bool { return false }
func checkOwner(_ string, info os.FileInfo, private bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return ErrState
	}
	mask := os.FileMode(0o022)
	if private {
		mask = 0o077
	}
	if info.Mode().Perm()&mask != 0 {
		return ErrState
	}
	return nil
}
func protectCreated(path string, directory bool) error {
	mode := os.FileMode(0o600)
	if directory {
		mode = 0o700
	}
	return os.Chmod(path, mode)
}
func lockFile(f *os.File) error            { return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) }
func unlockFile(f *os.File)                { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }
func replacePrivate(from, to string) error { return os.Rename(from, to) }
func syncDirectory(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
