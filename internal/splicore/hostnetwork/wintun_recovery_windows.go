package hostnetwork

import (
	"errors"
	"strings"
	"unsafe"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Recovery cannot turn an OpenAdapter handle into a CreateAdapter handle:
// closing an opened handle does not remove the orphan. SetupAPI removes exactly
// the Wintun device whose NetCfgInstanceId matches the durable random GUID.
func recoverWindowsAdapter(key Record) error {
	_, err := withWindowsAdapter(key, func(set windows.DevInfo, info *windows.DevInfoData) error {
		params := windows.RemoveDeviceParams{ClassInstallHeader: *windows.MakeClassInstallHeader(windows.DIF_REMOVE), Scope: windows.DI_REMOVEDEVICE_GLOBAL}
		if err := set.SetClassInstallParams(info, &params.ClassInstallHeader, uint32(unsafe.Sizeof(params))); err != nil {
			return err
		}
		if err := set.CallClassInstaller(windows.DIF_REMOVE, info); err != nil {
			return err
		}
		install, err := windows.SetupDiGetDeviceInstallParams(set, info)
		if err != nil {
			return err
		}
		if install.Flags&(windows.DI_NEEDREBOOT|windows.DI_NEEDRESTART) != 0 {
			return identity.Err(identity.Unavailable, "owned adapter removal pending administrator restart")
		}
		return nil
	})
	return err
}
func withWindowsAdapter(key Record, visit func(windows.DevInfo, *windows.DevInfoData) error) (bool, error) {
	if key.Adapter == nil || key.Adapter.Validate() != nil {
		return false, identity.Err(identity.Conflict, "unconfirmed Windows adapter identity")
	}
	class, err := windows.GUIDFromString("{4d36e972-e325-11ce-bfc1-08002be10318}")
	if err != nil {
		return false, err
	}
	set, err := windows.SetupDiGetClassDevsEx(&class, "", 0, 0, 0, "")
	if err != nil {
		return false, err
	}
	defer set.Close()
	for i := 0; i < 4096; i++ {
		info, err := set.EnumDeviceInfo(i)
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		h, err := set.OpenDevRegKey(info, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, registry.QUERY_VALUE)
		if errors.Is(err, windows.ERROR_KEY_DOES_NOT_EXIST) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			continue
		}
		if err != nil {
			return false, err
		}
		k := registry.Key(h)
		guid, _, e := k.GetStringValue("NetCfgInstanceId")
		k.Close()
		if errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
			continue
		}
		if e != nil {
			return false, e
		}
		if !strings.EqualFold(strings.Trim(guid, "{}"), string(key.Adapter.GUID)) {
			continue
		}
		service, err := set.DeviceRegistryProperty(info, windows.SPDRP_SERVICE)
		if err != nil || !strings.EqualFold(strings.TrimSpace(asString(service)), "wintun") {
			return false, identity.Err(identity.Conflict, "confirmed GUID has unrelated device service")
		}
		if visit != nil {
			if err := visit(set, info); err != nil {
				return true, err
			}
		}
		return true, nil
	}
	return false, identity.Err(identity.Unavailable, "Windows device enumeration limit exceeded")
}
func asString(v any) string { s, _ := v.(string); return s }
