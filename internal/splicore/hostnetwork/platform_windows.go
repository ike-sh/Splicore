package hostnetwork

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/nativetun"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type Platform struct {
	mu             sync.Mutex
	devices        map[string]nativetun.Device
	winINET        WinINETAPI
	wintun         WintunDriver
	authorizations map[string]Step
}

func NewPlatform() *Platform {
	return &Platform{devices: map[string]nativetun.Device{}, winINET: nativeWinINET{}, wintun: nativeWintunDriver{}, authorizations: map[string]Step{}}
}
func platformCapabilities() Capabilities {
	p := "elevation-required"
	if windows.GetCurrentProcessToken().IsElevated() {
		p = "elevated"
	}
	return Capabilities{TUN: "blocked-partial-construction", AutoRoute: "unsupported", Driver: DriverStatus(), Privilege: p, SystemProxy: "blocked-incomplete-ownership", LoopProtection: "auto-route-fail-closed"}
}
func (*Platform) Scope() string {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ""
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	machine, _, err := k.GetStringValue("MachineGuid")
	if err != nil || strings.TrimSpace(machine) == "" {
		return ""
	}
	return fmt.Sprintf("windows-machine:%x:user:%s", sha256.Sum256([]byte(machine)), user.User.Sid.String())
}
func (p *Platform) Device(name string) (nativetun.Device, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if d := p.devices[name]; d != nil {
		return d, nil
	}
	return nil, identity.Err(identity.Unavailable, "owned TUN device unavailable")
}

const proxyKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

func (p *Platform) Read(ctx context.Context, key Record) (*Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := cloneRecord(&key)
	if key.Kind == "windows-route" {
		return readWindowsRoute(ctx, key)
	}
	if key.Adapter != nil || key.Kind == "session" {
		// Partial candidates are selected by their retained creation handle.
		p.mu.Lock()
		owned, candidate := p.devices[key.Interface].(*windowsWintun)
		partial := candidate && !owned.configured && key.Kind == "interface"
		p.mu.Unlock()
		if !partial {
			if err := existingWindowsName(key); err != nil {
				return nil, err
			}
		}
		return p.readOwnedAdapter(key)
	}
	if key.Kind == "wininet" {
		s, err := p.winINET.Capture(ctx)
		if err != nil {
			return nil, err
		}
		out.WinINET = &s
		return out, out.Validate()
	}
	if key.Kind == "proxy" {
		k, err := registry.OpenKey(registry.CURRENT_USER, proxyKey, registry.QUERY_VALUE)
		if err != nil {
			return nil, err
		}
		defer k.Close()
		for name := range key.Proxy.Values {
			var value ProxyValue
			data, typ, err := k.GetValue(name, make([]byte, 16384))
			if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
				out.Proxy.Values[name] = value
				continue
			}
			if err != nil || data > 8192 {
				return nil, identity.Err(identity.Invalid, "unsupported system proxy value")
			}
			value.Present, value.Type = true, typ
			if typ == registry.DWORD {
				n, _, e := k.GetIntegerValue(name)
				if e != nil || n > 1<<32-1 {
					return nil, identity.Err(identity.Invalid, "invalid system proxy integer")
				}
				value.Number = uint32(n)
			} else if typ == registry.SZ {
				text, _, e := k.GetStringValue(name)
				if e != nil {
					return nil, e
				}
				value.Text = text
			} else {
				return nil, identity.Err(identity.Invalid, "unsupported system proxy registry type")
			}
			out.Proxy.Values[name] = value
		}
		return out, out.Validate()
	}
	iface, err := net.InterfaceByName(key.Interface)
	if err != nil {
		if key.Kind == "interface" || key.Kind == "address" || key.Kind == "route" {
			return nil, nil
		}
		return nil, err
	}
	out.Index = iface.Index
	switch key.Kind {
	case "interface":
		out.MTU = uint32(iface.MTU)
		return out, nil
	case "address":
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			if a.String() == key.Prefix {
				return out, nil
			}
		}
		return nil, nil
	case "route":
		table, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
		if err != nil {
			return nil, err
		}
		for _, r := range table {
			if r.InterfaceIndex == uint32(iface.Index) && r.DestinationPrefix.Prefix().String() == key.Prefix {
				if int(r.Metric) != key.Metric || r.Protocol != winipcfg.RouteProtocolNetMgmt || r.Loopback || r.Publish || r.AutoconfigureAddress {
					return nil, identity.Err(identity.Conflict, "external route attributes changed")
				}
				out.Gateway = r.NextHop.Addr().String()
				return out, nil
			}
		}
		return nil, nil
	default:
		return nil, identity.Err(identity.NotImplemented, "unsupported Windows network record")
	}
}
func (p *Platform) Write(ctx context.Context, key Record, value *Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if key.Adapter != nil && !p.authorized(key, value) {
		return identity.Err(identity.NotImplemented, "durable Windows adapter ownership authorization required")
	}
	if key.Kind == "windows-route" {
		if !p.authorized(key, value) {
			return identity.Err(identity.NotImplemented, "durable Windows route ownership required")
		}
		return writeWindowsRoute(ctx, key, value)
	}
	if key.Kind == "wininet" {
		if !p.authorized(key, value) {
			return identity.Err(identity.NotImplemented, "durable WinINET ownership authorization required")
		}
		if value == nil || value.WinINET == nil {
			return identity.Err(identity.Invalid, "missing WinINET target state")
		}
		before, err := p.winINET.Capture(ctx)
		if err != nil {
			return err
		}
		if !p.authorizedCurrent(key, &Record{Kind: "wininet", WinINET: &before}, value) {
			return identity.Err(identity.Conflict, "WinINET state changed after durable snapshot")
		}
		return applyWinINET(ctx, p.winINET, before, *value.WinINET)
	}
	// Schema-1 five-value proxy records remain readable for diagnosis, but cannot
	// authorize writes. Current activation uses one typed LAN WinINET snapshot.
	if key.Kind == "proxy" {
		return identity.Err(identity.NotImplemented, "Windows system proxy requires complete WinINET connection-state ownership")
	}
	// The pinned public constructor loses its adapter on StartSession failure.
	// Never enter a creation path whose partial ownership cannot be recovered.
	if key.Kind == "interface" && value != nil && (key.Adapter == nil || !p.authorized(key, value)) {
		return identity.Err(identity.NotImplemented, "Windows TUN requires recoverable partial-construction ownership")
	}
	if key.Kind == "session" {
		if !p.authorized(key, value) {
			return identity.Err(identity.NotImplemented, "durable Wintun session ownership required")
		}
		p.mu.Lock()
		d := p.devices[key.Interface]
		p.mu.Unlock()
		if d == nil {
			if value == nil {
				return nil
			}
			return identity.Err(identity.Unavailable, "Wintun adapter missing")
		}
		owned, ok := d.(*windowsWintun)
		if !ok || key.Adapter == nil || owned.identity != *key.Adapter {
			return identity.Err(identity.Conflict, "Wintun session identity changed")
		}
		if value == nil {
			return owned.closeSession()
		}
		return owned.Start()
	}
	if key.Kind == "interface" {
		p.mu.Lock()
		defer p.mu.Unlock()
		if value == nil {
			d := p.devices[key.Interface]
			if d == nil {
				return recoverWindowsAdapter(key)
			}
			owned, ok := d.(*windowsWintun)
			if !ok || key.Adapter == nil || owned.identity != *key.Adapter {
				return identity.Err(identity.Conflict, "Wintun handle owner changed")
			}
			err := d.Close()
			if err == nil {
				delete(p.devices, key.Interface)
			}
			return err
		}
		if _, err := net.InterfaceByName(key.Interface); err == nil {
			return identity.Err(identity.Conflict, "interface appeared before create")
		}
		candidate, err := createOwnedWintun(p.wintun, key.Interface, *key.Adapter)
		var d *windowsWintun
		if candidate != nil {
			d = &windowsWintun{ownedWintun: candidate, mtu: key.MTU}
			p.devices[key.Interface] = d
		}
		if err != nil {
			return identity.Err(identity.Unavailable, "TUN requires an available Wintun DLL and elevated privileges")
		}
		cleanup := func(cause error) error {
			e := d.Close()
			if e == nil {
				delete(p.devices, key.Interface)
			}
			return errors.Join(cause, e)
		}
		iface, e := net.InterfaceByName(key.Interface)
		if e != nil {
			return cleanup(e)
		}
		luid, e := winipcfg.LUIDFromIndex(uint32(iface.Index))
		if e != nil {
			return cleanup(e)
		}
		for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
			row, e := luid.IPInterface(family)
			if e != nil {
				return cleanup(e)
			}
			row.NLMTU = key.MTU
			row.DadTransmits = 0
			row.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
			if e = row.Set(); e != nil {
				return cleanup(e)
			}
		}
		d.configured = true
		return nil
	}
	iface, err := net.InterfaceByName(key.Interface)
	if err != nil {
		return err
	}
	if key.Index != 0 && iface.Index != key.Index {
		return identity.Err(identity.Conflict, "network interface identity changed")
	}
	luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
	if err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(key.Prefix)
	if err != nil {
		return err
	}
	switch key.Kind {
	case "address":
		if value == nil {
			return luid.DeleteIPAddress(prefix)
		}
		return luid.AddIPAddress(prefix)
	case "route":
		gateway, err := netip.ParseAddr(key.Gateway)
		if err != nil {
			return err
		}
		if value == nil {
			return luid.DeleteRoute(prefix, gateway)
		}
		return luid.AddRoute(prefix, gateway, uint32(key.Metric))
	default:
		return identity.Err(identity.NotImplemented, "unsupported Windows network mutation")
	}
}
func (*Platform) capturePlan(context.Context, client.TUNSettings, *Plan) error {
	// Fail closed until every outbound/DNS/server path has a protected underlay.
	return identity.Err(identity.NotImplemented, "Windows auto-route requires protected underlay integration")
}
func DriverStatus() string {
	// Never search the working directory or PATH for executable DLL code.
	program, err := os.Executable()
	if err != nil {
		return "unavailable"
	}
	path := filepath.Join(filepath.Dir(program), "wintun.dll")
	if _, err = os.Stat(path); err != nil {
		system, err := windows.GetSystemDirectory()
		if err != nil {
			return "missing"
		}
		path = filepath.Join(system, "wintun.dll")
	}
	h, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)
	if err != nil {
		return "missing"
	}
	defer windows.FreeLibrary(h)
	proc, err := windows.GetProcAddress(h, "WintunGetRunningDriverVersion")
	if err != nil {
		return "available-version-unknown"
	}
	n, _, _ := syscall.SyscallN(proc)
	if n == 0 {
		return "available-version-unknown"
	}
	return strconv.Itoa(int(n>>16)) + "." + strconv.Itoa(int(n&0xffff))
}
