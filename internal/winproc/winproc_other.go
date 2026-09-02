//go:build !windows

// Package winproc 只在 Windows 上有实现。这里保留一个空的包声明，
// 使 `go build ./...` 与 `go vet ./...` 在其他平台上不会因为
// "build constraints exclude all Go files" 而失败。
package winproc

import "os/exec"

// ConfigureNoWindow 在非 Windows 平台无需配置子进程窗口，因此为空操作。
func ConfigureNoWindow(_ *exec.Cmd) {}
