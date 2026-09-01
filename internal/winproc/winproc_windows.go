//go:build windows

// Package winproc 用 Win32 API 查询进程状态。
//
// 存在的理由：解析 `tasklist` 的文本输出是不可靠的。它的"没有匹配任务"提示会
// 随系统显示语言本地化——中文 Windows 输出 GBK 编码的"信息: 没有运行的任务…"，
// 既不以 "INFO:" 开头，也不是 UTF-8。据此判断进程是否存活会在非英文系统上
// 稳定误判为"进程仍然存活"。
//
// 直接问内核既没有这个问题，也不必为每次检查启动一个子进程。
package winproc

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// State 报告 pid 是否存活，以及该进程的镜像名是否就是 executable 的文件名。
//
// 进程不存在时返回 (false, false, nil)——这是正常情况，不是错误。
// alive 为 true 而 matches 为 false，说明该 PID 已被系统复用给了别的程序。
func State(pid int, executable string) (alive bool, matches bool, err error) {
	if pid <= 0 {
		return false, false, nil
	}
	const access = windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.SYNCHRONIZE
	handle, err := windows.OpenProcess(access, false, uint32(pid))
	if err != nil {
		// 进程已经不存在（ERROR_INVALID_PARAMETER）是最常见的情况。
		// 拿不到句柄时无法进一步判断，一律当作"不是我们要找的进程"。
		return false, false, nil
	}
	defer windows.CloseHandle(handle)

	// WaitForSingleObject 对进程句柄立即返回：已退出则 signaled，仍在跑则超时。
	// 比 GetExitCodeProcess 的 STILL_ACTIVE 可靠——后者会和"退出码恰好是 259"
	// 的进程混淆。
	event, err := windows.WaitForSingleObject(handle, 0)
	if err != nil {
		return false, false, fmt.Errorf("wait for process %d: %w", pid, err)
	}
	if event != uint32(windows.WAIT_TIMEOUT) {
		return false, false, nil
	}

	image, err := imageName(handle)
	if err != nil {
		// 进程活着但读不到镜像路径（通常是刚好退出或权限不足）。
		// 无法确认身份就不认，调用方会把它当作陈旧记录丢弃，而不会去动它。
		return true, false, nil
	}
	return true, equalFileName(image, executable), nil
}

func imageName(handle windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}

// equalFileName 只比对文件名，且大小写不敏感：daemon 状态文件里记的是启动时的
// 完整路径，而同一个程序可能通过不同路径（符号链接、大小写不同的盘符）启动。
func equalFileName(imagePath, executable string) bool {
	return strings.EqualFold(filepath.Base(imagePath), filepath.Base(executable))
}
