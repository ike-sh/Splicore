//go:build !linux && !windows

package netbench

func processResources() (int64, int64, int64, string) {
	return 0, 0, 0, "NOT EXECUTED: process metrics unsupported on this OS"
}
