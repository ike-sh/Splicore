//go:build !linux && !windows

package xray

import (
	"os"
	"os/exec"
)

func childEnvironment() []string   { return nil }
func executable(os.FileInfo) bool  { return false }
func secureDirectory(string) error { return unavailable("Xray platform unsupported") }
func secureFile(string) error      { return unavailable("Xray platform unsupported") }
func lockLease(*os.File) error     { return unavailable("Xray platform unsupported") }

type ownedProcess struct{}

func prepareProcess(*exec.Cmd) (*ownedProcess, error) {
	return nil, unavailable("Xray platform unsupported")
}
func (*ownedProcess) attach(*exec.Cmd) error { return unavailable("Xray platform unsupported") }
func (*ownedProcess) terminate(bool)         {}
func (*ownedProcess) release()               {}
func listenerOwned(int, uint16) bool         { return false }
