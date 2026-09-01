//go:build windows

package winproc

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestConfigureNoWindow 验证无窗口配置会设置目标标志、清除冲突标志并保留其他标志。
func TestConfigureNoWindow(t *testing.T) {
	cmd := &exec.Cmd{
		SysProcAttr: &syscall.SysProcAttr{
			CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS | windows.CREATE_NEW_CONSOLE,
		},
	}

	ConfigureNoWindow(cmd)

	if cmd.SysProcAttr == nil {
		t.Fatal("ConfigureNoWindow 必须初始化 SysProcAttr")
	}
	if !cmd.SysProcAttr.HideWindow {
		t.Fatal("ConfigureNoWindow 必须设置 HideWindow")
	}
	flags := cmd.SysProcAttr.CreationFlags
	if flags&windows.CREATE_NO_WINDOW == 0 {
		t.Fatal("ConfigureNoWindow 必须设置 CREATE_NO_WINDOW")
	}
	if flags&(windows.DETACHED_PROCESS|windows.CREATE_NEW_CONSOLE) != 0 {
		t.Fatal("ConfigureNoWindow 必须清除 DETACHED_PROCESS 和 CREATE_NEW_CONSOLE")
	}
	if flags&windows.CREATE_NEW_PROCESS_GROUP == 0 {
		t.Fatal("ConfigureNoWindow 不得清除 CREATE_NEW_PROCESS_GROUP 等其他标志")
	}
}

// TestConfigureNoWindowInitializesAttributes 验证缺少 SysProcAttr 时会自动创建配置对象。
func TestConfigureNoWindowInitializesAttributes(t *testing.T) {
	cmd := &exec.Cmd{}

	ConfigureNoWindow(cmd)

	if cmd.SysProcAttr == nil {
		t.Fatal("SysProcAttr 不能为空")
	}
	if !cmd.SysProcAttr.HideWindow {
		t.Fatal("必须设置 HideWindow")
	}
	if cmd.SysProcAttr.CreationFlags&windows.CREATE_NO_WINDOW == 0 {
		t.Fatal("必须设置 CREATE_NO_WINDOW")
	}
}

// sleepHelperEnv 让测试二进制以"长活子进程"的身份重新执行自己，
// 用来提供一个真实可控的 PID。
const sleepHelperEnv = "MCPX_TEST_WINPROC_SLEEP_HELPER"

func TestWinprocSleepHelper(t *testing.T) {
	if os.Getenv(sleepHelperEnv) != "1" {
		t.Skip("helper process: 仅在被其他测试重新执行时运行")
	}
	time.Sleep(30 * time.Second)
}

func startHelper(t *testing.T) *exec.Cmd {
	t.Helper()
	helper := exec.Command(os.Args[0], "-test.run=TestWinprocSleepHelper")
	helper.Env = append(os.Environ(), sleepHelperEnv+"=1")
	if err := helper.Start(); err != nil {
		t.Fatalf("start helper process: %v", err)
	}
	return helper
}

func TestStateReportsRunningProcess(t *testing.T) {
	helper := startHelper(t)
	defer func() {
		_ = helper.Process.Kill()
		_, _ = helper.Process.Wait()
	}()

	alive, matches, err := State(helper.Process.Pid, os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if !alive {
		t.Fatal("正在运行的进程必须报告为存活")
	}
	if !matches {
		t.Fatal("镜像名与测试二进制一致时必须匹配")
	}
}

// 这条是本文件的核心：进程不存在时必须报告 alive=false。
//
// 旧实现解析 `tasklist` 的文本输出，用 "INFO:" 前缀判断"没有匹配任务"。
// 该提示会随系统显示语言本地化（中文 Windows 输出 GBK 的"信息: …"），
// 于是在非英文系统上永远判定为存活，导致 `mcpx stop` 必然超时失败。
// Win32 查询与显示语言无关。
func TestStateReportsExitedProcess(t *testing.T) {
	helper := startHelper(t)
	pid := helper.Process.Pid
	if err := helper.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_, _ = helper.Process.Wait()

	alive, matches, err := State(pid, os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if alive {
		t.Fatal("已退出的进程必须报告为不存活（与系统显示语言无关）")
	}
	if matches {
		t.Fatal("不存活的进程不应报告为匹配")
	}
}

// PID 被系统复用给别的程序时，必须报告 alive=true 但 matches=false，
// 这样调用方会把状态文件当作陈旧记录丢弃，而不会去终止一个无关进程。
func TestStateDetectsMismatchedImage(t *testing.T) {
	helper := startHelper(t)
	defer func() {
		_ = helper.Process.Kill()
		_, _ = helper.Process.Wait()
	}()

	alive, matches, err := State(helper.Process.Pid, `C:\definitely\not\a\real\mcpx.exe`)
	if err != nil {
		t.Fatal(err)
	}
	if !alive {
		t.Fatal("进程仍在运行，应报告为存活")
	}
	if matches {
		t.Fatal("镜像名不同的进程不能被认成我们的 daemon")
	}
}

func TestStateRejectsInvalidPID(t *testing.T) {
	for _, pid := range []int{0, -1} {
		alive, matches, err := State(pid, os.Args[0])
		if err != nil || alive || matches {
			t.Fatalf("State(%d) = (%v, %v, %v)，期望 (false, false, nil)", pid, alive, matches, err)
		}
	}
}
