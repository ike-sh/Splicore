//go:build windows

package xray

import (
	"encoding/binary"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func childEnvironment() []string       { return []string{"SystemRoot=" + os.Getenv("SystemRoot")} }
func executable(info os.FileInfo) bool { return info.Mode().IsRegular() }

// Windows mode bits do not express ACLs. Protect the DACL and grant only the
// current user and SYSTEM; children inherit the restricted generation DACL.
func restrictPath(path string) error {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer token.Close()
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
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
func secureDirectory(path string) error { return restrictPath(path) }
func secureFile(path string) error      { return restrictPath(path) }
func lockLease(file *os.File) error {
	return windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
}

type ownedProcess struct {
	mu       sync.Mutex
	job      windows.Handle
	released bool
}

func prepareProcess(cmd *exec.Cmd) (*ownedProcess, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	runtime.KeepAlive(&info)
	if err != nil {
		_ = windows.CloseHandle(job)
		return nil, err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return &ownedProcess{job: job}, nil
}
func (p *ownedProcess) attach(cmd *exec.Cmd) error {
	handle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	return windows.AssignProcessToJobObject(p.job, handle)
}
func (p *ownedProcess) terminate(force bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.released {
		_ = windows.TerminateJobObject(p.job, 1)
	}
}
func (p *ownedProcess) release() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.released {
		_ = windows.CloseHandle(p.job)
		p.released = true
	}
}

var getTCPTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

func listenerOwned(pid int, port uint16) bool {
	var size uint32
	_, _, _ = getTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, 5, 0)
	if size < 4 || size > 16<<20 {
		return false
	}
	b := make([]byte, size)
	code, _, _ := getTCPTable.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, 5, 0)
	runtime.KeepAlive(b)
	runtime.KeepAlive(&size)
	if code != 0 {
		return false
	}
	count := binary.LittleEndian.Uint32(b[:4])
	if uint64(count)*24+4 > uint64(len(b)) {
		return false
	}
	for offset := 4; offset < 4+int(count)*24; offset += 24 {
		row := b[offset : offset+24]
		if binary.LittleEndian.Uint32(row[:4]) == 2 && binary.LittleEndian.Uint32(row[4:8]) == 0x0100007f && binary.BigEndian.Uint16(row[8:10]) == port && binary.LittleEndian.Uint32(row[20:24]) == uint32(pid) {
			return true
		}
	}
	return false
}
