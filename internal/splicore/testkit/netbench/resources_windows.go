package netbench

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

var memoryInfo = windows.NewLazySystemDLL("psapi.dll").NewProc("GetProcessMemoryInfo")
var handleCount = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessHandleCount")

func processResources() (rss, cpu, handles int64, detail string) {
	p := windows.CurrentProcess()
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(p, &created, &exited, &kernel, &user); err != nil {
		return 0, 0, 0, err.Error()
	}
	ticks := func(f windows.Filetime) uint64 { return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime) }
	cpu = int64(ticks(kernel)+ticks(user)) * 100
	var info struct {
		Size, Faults                                                                   uint32
		PeakRSS, RSS, PeakPaged, Paged, PeakNonPaged, NonPaged, Pagefile, PeakPagefile uintptr
	}
	info.Size = uint32(unsafe.Sizeof(info))
	if ok, _, err := memoryInfo.Call(uintptr(p), uintptr(unsafe.Pointer(&info)), uintptr(info.Size)); ok == 0 {
		return 0, cpu, 0, err.Error()
	}
	var count uint32
	if ok, _, err := handleCount.Call(uintptr(p), uintptr(unsafe.Pointer(&count))); ok == 0 {
		return int64(info.RSS), cpu, 0, err.Error()
	}
	return int64(info.RSS), cpu, int64(count), ""
}
