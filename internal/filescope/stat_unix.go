//go:build !windows

package filescope

import (
	"fmt"
	"os"
	"syscall"
)

func identity(info os.FileInfo) (string, error) {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", ErrState
	}
	return fmt.Sprintf("%d:%d", s.Dev, s.Ino), nil
}
func singleRegular(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && s.Nlink == 1
}
func openRead(root *os.Root, path string) (*os.File, error) {
	return root.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
