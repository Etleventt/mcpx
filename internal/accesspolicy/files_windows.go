//go:build windows

package accesspolicy

import (
	"golang.org/x/sys/windows"
	"os"
	"strings"
)

func isReparse(path string) bool {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return true
	}
	a, e := windows.GetFileAttributes(p)
	return e != nil || a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
func checkOwner(path string, _ os.FileInfo, private bool) error {
	sd, e := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return ErrState
	}
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return ErrState
	}
	owner, _, e := sd.Owner()
	if e != nil || !windows.EqualSid(owner, user.User.Sid) {
		return ErrState
	}
	if !private {
		return nil
	}
	expected, e := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)")
	if e != nil {
		return ErrState
	}
	actual := sd.String()
	suffix := expected.String()
	start := strings.Index(suffix, "D:")
	if start < 0 || !strings.HasSuffix(actual, suffix[start:]) {
		return ErrState
	}
	return nil
}
func protectCreated(path string, _ bool) error {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)")
	if e != nil {
		return e
	}
	acl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
func lockFile(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
}
func unlockFile(f *os.File) {
	_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &windows.Overlapped{})
}
func replacePrivate(from, to string) error {
	a, e := windows.UTF16PtrFromString(from)
	if e != nil {
		return e
	}
	b, e := windows.UTF16PtrFromString(to)
	if e != nil {
		return e
	}
	return windows.MoveFileEx(a, b, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
func syncDirectory(string) error { return nil }
