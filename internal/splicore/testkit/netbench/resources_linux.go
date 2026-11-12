package netbench

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

func processResources() (rss, cpu, handles int64, detail string) {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0, 0, 0, err.Error()
	}
	cpu = usage.Utime.Nano() + usage.Stime.Nano()
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, cpu, 0, err.Error()
	}
	fields := strings.Fields(string(b))
	if len(fields) < 2 {
		return 0, cpu, 0, "invalid statm"
	}
	pages, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, cpu, 0, err.Error()
	}
	rss = pages * int64(os.Getpagesize())
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return rss, cpu, 0, err.Error()
	}
	return rss, cpu, int64(len(fds)), ""
}
