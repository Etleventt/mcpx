//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"mcpx/internal/winproc"
)

const (
	createNewProcessGroup = 0x00000200
)

func configureBackgroundProcess(cmd *exec.Cmd) {
	// 复用统一的无窗口配置，再保留 daemon 所需的独立进程组。
	winproc.ConfigureNoWindow(cmd)
	cmd.SysProcAttr.CreationFlags |= createNewProcessGroup
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

// windowsBackgroundProcessState 走 Win32 API 查询，不解析 `tasklist` 的文本输出。
//
// 曾经的实现靠 `strings.HasPrefix(line, "INFO:")` 判断"进程不存在"，但那行提示
// 会随系统显示语言本地化：中文 Windows 输出 GBK 编码的"信息: 没有运行的任务…"，
// 前缀匹配永远失败。结果是进程被判定为始终存活，`mcpx stop` 必然等到超时报
// "did not exit after kill"，镜像名也会取到乱码而误报 "no longer matches"。
func windowsBackgroundProcessState(pid int, executable string) (bool, bool, error) {
	return winproc.State(pid, executable)
}
