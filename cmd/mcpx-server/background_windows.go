//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	createNewProcessGroup = 0x00000200
	detachedProcess       = 0x00000008
)

func configureBackgroundProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNewProcessGroup | detachedProcess}
}

func terminateBackgroundProcess(pid int, executable string, timeout time.Duration) (bool, error) {
	if pid <= 0 || pid == os.Getpid() {
		return false, fmt.Errorf("invalid daemon pid %d", pid)
	}
	alive, matches, err := windowsBackgroundProcessState(pid, executable)
	if err != nil {
		return false, err
	}
	if !alive || !matches {
		// PID 已经不存在，或者还活着但镜像名不是我们的可执行文件——后者说明
		// 这个 PID 已被系统复用给了别的程序。两种情况都意味着状态文件里记录的
		// daemon 早就没了，属于陈旧记录，调用方据此丢弃即可。
		//
		// 这里绝不能报错：报错会让调用方在删除状态文件之前就早退，陈旧记录
		// 永远留在盘上，后续每一次 `mcpx -d` 都会重复失败。也绝不能对不匹配的
		// 进程发信号——那是别人的进程。
		return false, nil
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false, fmt.Errorf("find daemon pid %d: %w", pid, err)
	}
	if err := process.Kill(); err != nil {
		return false, fmt.Errorf("kill daemon pid %d: %w", pid, err)
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		alive, _, err := windowsBackgroundProcessState(pid, executable)
		if err != nil {
			return false, err
		}
		if !alive {
			return true, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false, fmt.Errorf("daemon pid %d did not exit after kill", pid)
}

func discoverBackgroundProcesses(executable string) ([]int, error) {
	return nil, nil
}

func windowsBackgroundProcessState(pid int, executable string) (bool, bool, error) {
	output, err := exec.Command("tasklist", "/FI", "PID eq "+strconv.Itoa(pid), "/FO", "CSV", "/NH").Output()
	if err != nil {
		return false, false, err
	}
	line := strings.TrimSpace(string(output))
	if line == "" || strings.HasPrefix(line, "INFO:") {
		return false, false, nil
	}
	first := line
	if index := strings.Index(first, ","); index >= 0 {
		first = first[:index]
	}
	image := strings.Trim(first, "\" ")
	return true, strings.EqualFold(image, filepath.Base(executable)), nil
}
