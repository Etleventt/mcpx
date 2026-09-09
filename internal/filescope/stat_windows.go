package filescope

import "os"

// Windows has no restricted-mode implementation in this release. Never downgrade.
func identity(info os.FileInfo) (string, error)             { return "", ErrState }
func singleRegular(info os.FileInfo) bool                   { return false }
func openRead(root *os.Root, path string) (*os.File, error) { return nil, ErrDenied }
