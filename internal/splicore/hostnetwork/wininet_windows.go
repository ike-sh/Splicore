//go:build windows

package hostnetwork

import (
	"context"
	"runtime"
	"unsafe"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"golang.org/x/sys/windows"
)

// Layout follows the installed Windows SDK 10.0.26100.0 wininet.h. uint64
// provides the union's FILETIME/pointer alignment on Windows amd64/arm64.
type internetPerConnOption struct {
	Option uint32
	Value  uint64
}
type internetPerConnList struct {
	Size        uint32
	Connection  *uint16
	Count       uint32
	OptionError uint32
	Options     *internetPerConnOption
}

var winINETDLL = windows.NewLazySystemDLL("wininet.dll")
var internetQueryOption = winINETDLL.NewProc("InternetQueryOptionW")
var internetSetOption = winINETDLL.NewProc("InternetSetOptionW")
var globalFree = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalFree")
var globalSize = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalSize")

type nativeWinINET struct{}

func boundedGlobalString(option *internetPerConnOption) (string, error) {
	ptr := *(**uint16)(unsafe.Pointer(&option.Value))
	if ptr == nil {
		return "", nil
	}
	// The allocation and its length belong to WinINET, never a Go backing array.
	defer globalFree.Call(uintptr(unsafe.Pointer(ptr)))
	size, _, _ := globalSize.Call(uintptr(unsafe.Pointer(ptr)))
	if size < 2 || size > 8194 || size%2 != 0 {
		return "", identity.Err(identity.Invalid, "unsupported WinINET string size")
	}
	data := unsafe.Slice(ptr, int(size/2))
	for i, c := range data {
		if c == 0 {
			return windows.UTF16ToString(data[:i]), nil
		}
	}
	return "", identity.Err(identity.Invalid, "unterminated WinINET string")
}

func (nativeWinINET) Capture(ctx context.Context) (WinINETSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return WinINETSnapshot{}, err
	}
	options := []internetPerConnOption{{Option: 10}, {Option: 2}, {Option: 3}, {Option: 4}, {Option: 5}, {Option: 6}, {Option: 7}}
	list := internetPerConnList{Count: uint32(len(options)), Options: &options[0]}
	list.Size = uint32(unsafe.Sizeof(list))
	size := list.Size
	ok, _, err := internetQueryOption.Call(0, 75, uintptr(unsafe.Pointer(&list)), uintptr(unsafe.Pointer(&size)))
	runtime.KeepAlive(options)
	// Free even returned allocations on a failed/partial query.
	var values [3]string
	var textErr error
	for i, index := range []int{1, 2, 3} {
		v, e := boundedGlobalString(&options[index])
		values[i] = v
		if e != nil {
			textErr = e
		}
	}
	secondary, e := boundedGlobalString(&options[5])
	if e != nil {
		textErr = e
	}
	if ok == 0 {
		return WinINETSnapshot{}, err
	}
	if textErr != nil {
		return WinINETSnapshot{}, textErr
	}
	s := WinINETSnapshot{Flags: uint32(options[0].Value), Server: values[0], Bypass: values[1], PAC: values[2], AutoDiscovery: uint32(options[4].Value), SecondaryPAC: secondary, ReloadMinutes: uint32(options[6].Value)}
	return s, s.Validate()
}

func (nativeWinINET) Set(ctx context.Context, option uint32, s WinINETSnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	o := internetPerConnOption{Option: option}
	var text *uint16
	var err error
	switch option {
	case 1:
		o.Value = uint64(s.Flags)
	case 5:
		o.Value = uint64(s.AutoDiscovery)
	case 7:
		o.Value = uint64(s.ReloadMinutes)
	case 2, 3, 4, 6:
		value := s.Server
		if option == 3 {
			value = s.Bypass
		}
		if option == 4 {
			value = s.PAC
		}
		if option == 6 {
			value = s.SecondaryPAC
		}
		text, err = windows.UTF16PtrFromString(value)
		if err != nil {
			return err
		}
		*(**uint16)(unsafe.Pointer(&o.Value)) = text
	default:
		return identity.Err(identity.Invalid, "unsupported WinINET mutation option")
	}
	list := internetPerConnList{Count: 1, Options: &o}
	list.Size = uint32(unsafe.Sizeof(list))
	ok, _, err := internetSetOption.Call(0, 75, uintptr(unsafe.Pointer(&list)), uintptr(list.Size))
	runtime.KeepAlive(text)
	runtime.KeepAlive(o)
	runtime.KeepAlive(list)
	if ok == 0 {
		return err
	}
	return nil
}
func (nativeWinINET) Notify(ctx context.Context, option uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if option != 39 && option != 37 {
		return identity.Err(identity.Invalid, "unsupported WinINET notification")
	}
	ok, _, err := internetSetOption.Call(0, uintptr(option), 0, 0)
	if ok == 0 {
		return err
	}
	return nil
}

func (*Platform) Transitions(key Record, before, after *Record) ([]*Record, error) {
	return winINETRecordTransitions(key, before, after)
}
func (p *Platform) FinalizeRestore(ctx context.Context, key Record) error {
	if key.Kind == "wininet" {
		return notifyWinINET(ctx, p.winINET)
	}
	return nil
}
func (*Platform) SystemProxyPlan(endpoint string) ([]Record, error) { return WinINETPlan(endpoint) }
