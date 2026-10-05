package native

import (
	"context"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
	"net/netip"
	"os"
)

// The managed direct-only profile leaves interface selection to the OS.
// It has no TUN, auto-detect, WiFi, shell or network-reset policy. Avoid starting
// upstream's asynchronous interface monitor, which races its post-start flag.
// This is production composition, equally used in tests and normal runtime.
type serverPlatform struct{}

var _ adapter.PlatformInterface = serverPlatform{}

func (serverPlatform) Initialize(adapter.NetworkManager) error     { return nil }
func (serverPlatform) UsePlatformAutoDetectInterfaceControl() bool { return false }
func (serverPlatform) AutoDetectInterfaceControl(int) error        { return os.ErrInvalid }
func (serverPlatform) UsePlatformInterface() bool                  { return false }
func (serverPlatform) OpenInterface(*tun.Options, option.TunPlatformOptions) (tun.Tun, error) {
	return nil, os.ErrInvalid
}
func (serverPlatform) ProcessPlatformOptions(option.TunPlatformOptions) error { return os.ErrInvalid }
func (serverPlatform) UsePlatformDefaultInterfaceMonitor() bool               { return true }
func (serverPlatform) CreateDefaultInterfaceMonitor(logger.Logger) tun.DefaultInterfaceMonitor {
	return staticMonitor{}
}
func (serverPlatform) UsePlatformNetworkInterfaces() bool { return false }
func (serverPlatform) NetworkInterfaces() ([]adapter.NetworkInterface, error) {
	return nil, os.ErrInvalid
}
func (serverPlatform) UnderNetworkExtension() bool                     { return false }
func (serverPlatform) NetworkExtensionIncludeAllNetworks() bool        { return false }
func (serverPlatform) ClearDNSCache()                                  {}
func (serverPlatform) RequestPermissionForWIFIState() error            { return os.ErrInvalid }
func (serverPlatform) ReadWIFIState(context.Context) adapter.WIFIState { return adapter.WIFIState{} }
func (serverPlatform) UsePlatformConnectionOwnerFinder() bool          { return false }
func (serverPlatform) FindConnectionOwner(*adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	return nil, os.ErrInvalid
}
func (serverPlatform) UsePlatformWIFIMonitor() bool                 { return false }
func (serverPlatform) UsePlatformNotification() bool                { return false }
func (serverPlatform) SendNotification(*adapter.Notification) error { return os.ErrInvalid }
func (serverPlatform) CancelNotification(string, int32) error       { return os.ErrInvalid }
func (serverPlatform) MyInterfaceAddress() []netip.Addr             { return nil }
func (serverPlatform) UsePlatformNeighborResolver() bool            { return false }
func (serverPlatform) StartNeighborMonitor(adapter.NeighborUpdateListener) error {
	return os.ErrInvalid
}
func (serverPlatform) CloseNeighborMonitor(adapter.NeighborUpdateListener) error {
	return os.ErrInvalid
}
func (serverPlatform) UsePlatformShell() bool    { return false }
func (serverPlatform) CheckPlatformShell() error { return os.ErrInvalid }
func (serverPlatform) OpenShellSession(*adapter.PlatformUser, string, []string, string, int32, int32) (adapter.ShellSession, error) {
	return nil, os.ErrInvalid
}
func (serverPlatform) LookupUser(string) (*adapter.PlatformUser, error) { return nil, os.ErrInvalid }
func (serverPlatform) LookupSFTPServer() (string, error)                { return "", os.ErrInvalid }
func (serverPlatform) ReadSystemSSHHostKey() ([]byte, error)            { return nil, os.ErrInvalid }
func (serverPlatform) TailscaleHostname() string                        { return "" }
func (serverPlatform) UsePlatformBridge() bool                          { return false }
func (serverPlatform) CreateBridge(adapter.BridgeOptions) (adapter.BridgeSession, error) {
	return nil, os.ErrInvalid
}

type staticMonitor struct{}

func (staticMonitor) Start() error                         { return nil }
func (staticMonitor) Close() error                         { return nil }
func (staticMonitor) DefaultInterface() *control.Interface { return nil }
func (staticMonitor) OverrideAndroidVPN() bool             { return false }
func (staticMonitor) AndroidVPNEnabled() bool              { return false }
func (staticMonitor) RegisterCallback(tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	return nil
}
func (staticMonitor) UnregisterCallback(*list.Element[tun.DefaultInterfaceUpdateCallback]) {}
func (staticMonitor) RegisterMyInterface(string)                                           {}
func (staticMonitor) MyInterfaces() []string                                               { return nil }
