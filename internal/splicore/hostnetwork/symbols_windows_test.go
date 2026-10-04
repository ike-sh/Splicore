package hostnetwork

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsReadOnlyAPISymbolsAndABI(t *testing.T) {
	// Resolves entry points; never invokes a network/proxy/adapter mutation.
	for dll, names := range map[string][]string{"wininet.dll": {"InternetQueryOptionW", "InternetSetOptionW"}, "kernel32.dll": {"GlobalFree", "GlobalSize"}, "iphlpapi.dll": {"GetIpForwardTable2", "CreateIpForwardEntry2", "DeleteIpForwardEntry2", "ConvertInterfaceLuidToGuid", "ConvertInterfaceGuidToLuid"}, "setupapi.dll": {"SetupDiGetClassDevsExW", "SetupDiOpenDevRegKey", "SetupDiGetDeviceRegistryPropertyW", "SetupDiSetClassInstallParamsW", "SetupDiCallClassInstaller"}} {
		module := windows.NewLazySystemDLL(dll)
		for _, name := range names {
			if err := module.NewProc(name).Find(); err != nil {
				t.Fatal(dll, name, err)
			}
		}
	}
	if unsafe.Sizeof(uintptr(0)) == 8 && (unsafe.Sizeof(internetPerConnOption{}) != 16 || unsafe.Offsetof(internetPerConnOption{}.Value) != 8 || unsafe.Sizeof(internetPerConnList{}) != 32) {
		t.Fatal("WinINET ABI mismatch")
	}
}
