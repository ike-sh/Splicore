//go:build linux

package xray

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

func childEnvironment() []string { return []string{"LANG=C"} }
func executable(info os.FileInfo) bool {
	return info.Mode().Perm()&0111 != 0 && info.Mode().Perm()&0022 == 0
}
func secureDirectory(path string) error {
	i, err := os.Lstat(path)
	if err != nil || !i.IsDir() || i.Mode().Perm()&0077 != 0 {
		return unavailable("unsafe runtime directory")
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || s.Uid != uint32(os.Geteuid()) {
		return unavailable("runtime directory owner mismatch")
	}
	return nil
}
func secureFile(path string) error {
	i, err := os.Lstat(path)
	if err != nil || !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 {
		return unavailable("unsafe runtime file")
	}
	return nil
}
func lockLease(file *os.File) error {
	i, err := file.Stat()
	if err != nil || !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 {
		return unavailable("unsafe runtime lease")
	}
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

type ownedProcess struct {
	mu       sync.Mutex
	process  *os.Process
	released bool
}

func prepareProcess(cmd *exec.Cmd) (*ownedProcess, error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	return &ownedProcess{}, nil
}
func (p *ownedProcess) attach(cmd *exec.Cmd) error { p.process = cmd.Process; return nil }
func (p *ownedProcess) terminate(force bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.released || p.process == nil {
		return
	}
	if force {
		_ = p.process.Kill()
	} else {
		_ = p.process.Signal(syscall.SIGTERM)
	}
}
func (p *ownedProcess) release() { p.mu.Lock(); p.released = true; p.mu.Unlock() }

// A port probe alone could mistake an unrelated listener for this child.
// Match the expected loopback LISTEN socket inode to the owned PID's fd table.
func listenerOwned(pid int, port uint16) bool {
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return false
	}
	defer f.Close()
	expected := fmt.Sprintf("0100007F:%04X", port)
	inodes := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 9 && fields[1] == expected && fields[3] == "0A" {
			inodes["socket:["+fields[9]+"]"] = true
		}
	}
	if len(inodes) == 0 {
		return false
	}
	dir := "/proc/" + strconv.Itoa(pid) + "/fd"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		target, err := os.Readlink(dir + "/" + entry.Name())
		if err == nil && inodes[target] {
			return true
		}
	}
	return false
}
