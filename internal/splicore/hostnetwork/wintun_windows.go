package hostnetwork

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type nativeWintunDriver struct{}
type windowsWintun struct {
	*ownedWintun
	mtu        uint32
	configured bool // Platform.mu; construction failures still own their handle
}
type nativeWintunAdapter struct{ adapter *wintun.Adapter }
type nativeWintunSession struct {
	session wintun.Session
	quit    windows.Handle
	mu      sync.Mutex
	ended   bool
}

func (nativeWintunDriver) Create(name string, id WindowsAdapterIdentity) (WintunAdapter, error) {
	guid, err := windows.GUIDFromString("{" + string(id.GUID) + "}")
	if err != nil {
		return nil, err
	}
	// Public pinned wrapper searches only application directory and System32.
	a, err := wintun.CreateAdapter(name, "Splicore", &guid)
	if a == nil {
		return nil, err
	}
	owned := &nativeWintunAdapter{a}
	actual, verifyErr := owned.GUID()
	if err != nil || verifyErr != nil || actual != id.GUID {
		// Native CloseAdapter is void and closes this exact creation handle.
		// Reject a broken requested-GUID contract synchronously: do not leave an
		// adapter whose identity was never durably authorized for crash recovery.
		_ = owned.Close()
		return nil, identity.Err(identity.Conflict, "native Wintun creation identity unverified")
	}
	return owned, nil
}
func (nativeWintunDriver) Preflight() error {
	program, err := os.Executable()
	if err != nil {
		return err
	}
	path := filepath.Join(filepath.Dir(program), "wintun.dll")
	if _, err = os.Stat(path); err != nil {
		system, e := windows.GetSystemDirectory()
		if e != nil {
			return e
		}
		path = filepath.Join(system, "wintun.dll")
	}
	h, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return identity.Err(identity.Unavailable, "operator-supplied Wintun DLL unavailable")
	}
	defer windows.FreeLibrary(h)
	for _, symbol := range []string{"WintunCreateAdapter", "WintunCloseAdapter", "WintunGetAdapterLUID", "WintunSetLogger", "WintunStartSession", "WintunEndSession", "WintunGetReadWaitEvent", "WintunReceivePacket", "WintunReleaseReceivePacket", "WintunAllocateSendPacket", "WintunSendPacket"} {
		if _, err = windows.GetProcAddress(h, symbol); err != nil {
			return identity.Err(identity.Unavailable, "Wintun API contract incomplete")
		}
	}
	return nil
}
func (a *nativeWintunAdapter) GUID() (identity.ID, error) {
	g, err := winipcfg.LUID(a.adapter.LUID()).GUID()
	if err != nil {
		return "", err
	}
	return identity.ID(strings.ToLower(strings.Trim(g.String(), "{}"))), nil
}
func (a *nativeWintunAdapter) StartSession() (WintunSession, error) {
	s, err := a.adapter.StartSession(0x800000)
	if err != nil {
		return nil, err
	}
	quit, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		s.End()
		return nil, err
	}
	return &nativeWintunSession{session: s, quit: quit}, nil
}
func (a *nativeWintunAdapter) Close() error {
	// WintunCloseAdapter is VOID in the official C API. The pinned Go wrapper
	// interprets its unspecified return register as BOOL; it is not an OS error.
	// Its symbol has already been resolved by CreateAdapter. Manager verifies
	// actual removal separately through the GUID after closing the owned handle.
	_ = a.adapter.Close()
	return nil
}
func (s *nativeWintunSession) ReadPacket() ([]byte, error) {
	for {
		packet, err := s.session.ReceivePacket()
		if err == nil {
			copy := append([]byte(nil), packet...)
			s.session.ReleaseReceivePacket(packet)
			return copy, nil
		}
		if !errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			return nil, err
		}
		// Ring exhaustion is readiness, not a failed-operation retry. Both the
		// driver's borrowed event and our cancellation event bound this wait.
		index, err := windows.WaitForMultipleObjects([]windows.Handle{s.quit, s.session.ReadWaitEvent()}, false, windows.INFINITE)
		if err != nil {
			return nil, err
		}
		if index == windows.WAIT_OBJECT_0 {
			return nil, os.ErrClosed
		}
	}
}
func (s *nativeWintunSession) WritePacket(packet []byte) error {
	p, err := s.session.AllocateSendPacket(len(packet))
	if err != nil {
		return err
	}
	copy(p, packet)
	s.session.SendPacket(p)
	return nil
}
func (s *nativeWintunSession) Interrupt() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended || s.quit == 0 {
		return nil
	}
	return windows.SetEvent(s.quit)
}
func (s *nativeWintunSession) End() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ended {
		s.session.End()
		s.ended = true
	}
	if s.quit == 0 {
		return nil
	}
	err := windows.CloseHandle(s.quit)
	if err == nil {
		s.quit = 0
	}
	return err
}

func (p *Platform) OwnershipRecords(generation, owner identity.ID, desired []Record) ([]Record, error) {
	for _, r := range desired {
		if r.Kind == "interface" {
			if d, ok := p.wintun.(interface{ Preflight() error }); ok {
				if err := d.Preflight(); err != nil {
					return nil, err
				}
			}
		}
	}
	return windowsOwnershipRecords(generation, owner, desired)
}
func (p *Platform) Authorize(g Generation) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if g.ID.Validate() != nil || g.Owner.Validate() != nil {
		return identity.Err(identity.Corrupt, "Windows mutation authorization invalid")
	}
	for _, s := range g.Steps {
		if s.After != nil && s.After.Adapter != nil && (s.After.Adapter.Generation != g.ID || s.After.Adapter.Owner != g.Owner) {
			return identity.Err(identity.Corrupt, "Windows mutation generation mismatch")
		}
		if s.After != nil && s.After.WindowsRoute != nil && (s.After.WindowsRoute.Generation != g.ID || s.After.WindowsRoute.Owner != g.Owner) {
			return identity.Err(identity.Corrupt, "Windows route generation mismatch")
		}
	}
	for _, s := range g.Steps {
		s.Key = *cloneRecord(&s.Key)
		s.Before = cloneRecord(s.Before)
		s.After = cloneRecord(s.After)
		p.authorizations[s.Key.key()] = s
	}
	return nil
}
func (p *Platform) authorizedCurrent(key Record, current, target *Record) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.authorizations[key.key()]
	if !ok {
		return false
	}
	if equal(target, s.Before) {
		return equal(current, s.Before) || knownTransition(current, s)
	}
	return equal(target, s.After) && equal(current, s.Before)
}
func (p *Platform) authorized(key Record, target *Record) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.authorizations[key.key()]
	if !ok {
		return false
	}
	if target == nil {
		return s.Before == nil
	}
	return equal(target, s.Before) || equal(target, s.After)
}

func (p *Platform) readOwnedAdapter(key Record) (*Record, error) {
	p.mu.Lock()
	d := p.devices[key.Interface]
	partial := false
	if owned, ok := d.(*windowsWintun); ok && key.Kind == "interface" {
		if key.Adapter == nil || owned.identity != *key.Adapter {
			p.mu.Unlock()
			return nil, identity.Err(identity.Conflict, "Wintun candidate owner changed")
		}
		partial = !owned.configured
	}
	p.mu.Unlock()
	// A partial candidate is an exact process-owned handle, even when GUID or
	// MTU readback failed. Keep it visible to compensation; never identify it by
	// a guessed display name or lose it because the requested GUID is absent.
	if partial {
		return cloneRecord(&key), nil
	}
	if key.Kind == "session" {
		if d == nil {
			return nil, nil
		}
		owned, ok := d.(*windowsWintun)
		if !ok || !owned.started() {
			return nil, nil
		}
		if key.Adapter == nil || owned.identity != *key.Adapter {
			return nil, identity.Err(identity.Conflict, "Wintun session owner changed")
		}
		return cloneRecord(&key), nil
	}
	if key.Adapter == nil {
		return nil, identity.Err(identity.NotImplemented, "legacy Windows adapter identity unavailable")
	}
	guid, err := windows.GUIDFromString("{" + string(key.Adapter.GUID) + "}")
	if err != nil {
		return nil, err
	}
	luid, err := winipcfg.LUIDFromGUID(&guid)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_NOT_FOUND) {
		if key.Kind == "interface" {
			found, e := withWindowsAdapter(key, nil)
			if e != nil {
				return nil, e
			}
			if found {
				out := cloneRecord(&key)
				out.Index = 0
				return out, nil
			}
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	row, err := luid.Interface()
	if err != nil {
		return nil, err
	}
	if row.Alias() != key.Interface {
		return nil, identity.Err(identity.Conflict, "Wintun alias changed")
	}
	out := cloneRecord(&key)
	out.Index = int(row.InterfaceIndex)
	if key.Kind == "interface" {
		v, e := luid.IPInterface(windows.AF_INET)
		if e != nil {
			return nil, e
		}
		out.MTU = v.NLMTU
		return out, nil
	}
	prefix, err := netip.ParsePrefix(key.Prefix)
	if err != nil {
		return nil, err
	}
	v, err := luid.IPAddress(prefix.Addr())
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if int(v.OnLinkPrefixLength) != prefix.Bits() {
		return nil, identity.Err(identity.Conflict, "owned Windows address changed")
	}
	return out, nil
}

func existingWindowsName(key Record) error {
	iface, err := net.InterfaceByName(key.Interface)
	if err != nil {
		return nil
	}
	luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
	if err != nil {
		return err
	}
	guid, err := luid.GUID()
	if err != nil {
		return err
	}
	actual := identity.ID(strings.ToLower(strings.Trim(guid.String(), "{}")))
	if key.Adapter == nil || actual != key.Adapter.GUID {
		return identity.Err(identity.Conflict, "unrelated adapter uses requested display name")
	}
	return nil
}
