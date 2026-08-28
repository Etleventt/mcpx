//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func configureBackgroundProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

func terminateBackgroundProcess(pid int, executable string, timeout time.Duration) (bool, error) {
	if pid <= 0 || pid == os.Getpid() {
		return false, fmt.Errorf("invalid daemon pid %d", pid)
	}
	alive, err := backgroundProcessAlive(pid)
	if err != nil {
		return false, err
	}
	if !alive {
		return false, nil
	}
	matches, err := backgroundProcessMatches(pid, executable)
	if err != nil {
		return false, fmt.Errorf("verify daemon pid %d: %w", pid, err)
	}
	if !matches {
		// 进程还活着，但命令行不是我们的可执行文件，说明这个 PID 已经被系统
		// 复用给了别的程序。状态文件里的记录是陈旧的，调用方据此丢弃即可。
		//
		// 这里绝不能报错：报错会让调用方在删除状态文件之前就早退，陈旧记录
		// 永远留在盘上，后续每一次 `mcpx -d` 都会重复失败。也绝不能对不匹配的
		// 进程发信号——那是别人的进程。
		return false, nil
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return false, nil
		}
		return false, fmt.Errorf("terminate daemon pid %d: %w", pid, err)
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		alive, err := backgroundProcessAlive(pid)
		if err != nil {
			return false, err
		}
		if !alive {
			return true, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return false, fmt.Errorf("kill daemon pid %d: %w", pid, err)
	}
	return true, nil
}

func backgroundProcessAlive(pid int) (bool, error) {
	err := syscall.Kill(pid, 0)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, syscall.ESRCH):
		return false, nil
	case errors.Is(err, syscall.EPERM):
		return true, nil
	default:
		return false, fmt.Errorf("check daemon pid %d: %w", pid, err)
	}
}

func backgroundProcessMatches(pid int, executable string) (bool, error) {
	output, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "command=").Output()
	if err != nil {
		return false, err
	}
	return backgroundCommandMatches(strings.TrimSpace(string(output)), executable), nil
}

func discoverBackgroundProcesses(executable string) ([]int, error) {
	output, err := exec.Command("ps", "-axo", "pid=,sess=,command=").Output()
	if err != nil {
		return nil, err
	}
	return parseDetachedBackgroundProcesses(string(output), executable), nil
}

func parseDetachedBackgroundProcesses(output, executable string) []int {
	pids := make([]int, 0, 1)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil || pid <= 0 || pid == os.Getpid() {
			continue
		}
		sessionID, err := strconv.Atoi(fields[1])
		if err != nil || sessionID != pid {
			continue
		}
		commandStart := strings.Index(line, fields[2])
		if commandStart < 0 || !backgroundCommandMatches(strings.TrimSpace(line[commandStart:]), executable) {
			continue
		}
		pids = append(pids, pid)
	}
	return pids
}

func backgroundCommandMatches(command, executable string) bool {
	executable = filepath.Clean(strings.TrimSpace(executable))
	command = strings.TrimSpace(command)
	if command == "" || executable == "" {
		return false
	}
	return command == executable || strings.HasPrefix(command, executable+" ")
}
