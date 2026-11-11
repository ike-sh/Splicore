package hostnetwork

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsReadOnlyAPISymbolsAndABI(t *testing.T) {
	// Resolves entry points; never invokes a network/adapter mutation.
	for dll, names := range map[string][]string{"iphlpapi.dll": {"GetIpForwardTable2", "CreateIpForwardEntry2", "DeleteIpForwardEntry2", "ConvertInterfaceLuidToGuid", "ConvertInterfaceGuidToLuid"}, "setupapi.dll": {"SetupDiGetClassDevsExW", "SetupDiOpenDevRegKey", "SetupDiGetDeviceRegistryPropertyW", "SetupDiSetClassInstallParamsW", "SetupDiCallClassInstaller"}} {
		module := windows.NewLazySystemDLL(dll)
		for _, name := range names {
			if err := module.NewProc(name).Find(); err != nil {
				t.Fatal(dll, name, err)
			}
		}
	}
}
