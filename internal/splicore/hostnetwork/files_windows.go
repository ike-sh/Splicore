package hostnetwork

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"golang.org/x/sys/windows"
)

func privateFile(i os.FileInfo) error {
	if !i.Mode().IsRegular() && !i.IsDir() {
		return identity.Err(identity.Invalid, "unsafe network recovery file")
	}
	return nil
}

// Validate the owner and every DACL grant. Existing files are never re-ACL'd.
func privatePath(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || owner.String() != user.User.Sid.String() {
		return identity.Err(identity.Invalid, "network recovery owner invalid")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return identity.Err(identity.Invalid, "network recovery DACL missing")
	}
	sddl := sd.String()
	start := strings.Index(sddl, "D:")
	if start < 0 {
		return identity.Err(identity.Invalid, "network recovery DACL invalid")
	}
	part := sddl[start+2:]
	if end := strings.Index(part, "S:"); end >= 0 {
		part = part[:end]
	}
	ace := regexp.MustCompile(`\(A;[A-Z]*;(?:FA|0x1f01ff);;;(?:SY|` + regexp.QuoteMeta(user.User.Sid.String()) + `)\)`)
	grants := ace.FindAllString(part, -1)
	remaining := ace.ReplaceAllString(part, "")
	if len(grants) < 1 || strings.Trim(remaining, "PAI") != "" {
		return identity.Err(identity.Invalid, "network recovery permissions too broad")
	}
	return nil
}
func privateDirectory(path string) error {
	if resolved, err := filepath.EvalSymlinks(filepath.Dir(path)); err != nil || resolved != filepath.Dir(path) {
		return identity.Err(identity.Invalid, "network recovery parent is unsafe")
	}
	info, prior := os.Lstat(path)
	if prior == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return identity.Err(identity.Invalid, "unsafe recovery directory")
		}
		return privatePath(path)
	}
	if !os.IsNotExist(prior) {
		return prior
	}
	if err := os.Mkdir(path, 0700); err != nil {
		return err
	}
	i, err := os.Lstat(path)
	if err != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
		return identity.Err(identity.Invalid, "unsafe network recovery directory")
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return err
	}
	return privatePath(path)
}
func lockDirectory(path string) (*os.File, error) {
	name := filepath.Join(path, ".lock")
	if i, err := os.Lstat(name); err == nil && (!i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 || privatePath(name) != nil) {
		return nil, identity.Err(identity.Invalid, "unsafe network recovery lock")
	}
	f, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = privatePath(name); err != nil {
		f.Close()
		return nil, err
	}
	var overlapped windows.Overlapped
	if err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped); err != nil {
		f.Close()
		return nil, identity.Err(identity.Unavailable, "network recovery directory already owned")
	}
	return f, nil
}
func replaceFile(from, to string) error {
	f, e := windows.UTF16PtrFromString(from)
	if e != nil {
		return e
	}
	t, e := windows.UTF16PtrFromString(to)
	if e != nil {
		return e
	}
	return windows.MoveFileEx(f, t, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
func syncDirectory(string) error { return nil } // atomic replace uses WRITE_THROUGH; real power-loss qualification is pending
