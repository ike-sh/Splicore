package hostnetwork

import (
	"context"
	"net/netip"
	"strings"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func readWindowsRoute(ctx context.Context, key Record) (*Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	want := key.WindowsRoute
	if want == nil || want.Validate() != nil {
		return nil, identity.Err(identity.Invalid, "invalid Windows route snapshot")
	}
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	var found *Record
	for _, row := range rows {
		if row.DestinationPrefix.Prefix().String() != want.Destination {
			continue
		}
		guid, e := row.InterfaceLUID.GUID()
		if e != nil {
			return nil, e
		}
		if !strings.EqualFold(strings.Trim(guid.String(), "{}"), string(want.InterfaceGUID)) || row.InterfaceIndex != want.Index || row.NextHop.Addr().String() != want.NextHop || row.Metric != want.Metric || row.Protocol != winipcfg.RouteProtocolNetMgmt || row.Loopback || row.Publish || row.AutoconfigureAddress || row.SitePrefixLength != 0 {
			return nil, identity.Err(identity.Conflict, "unrelated Windows route attributes preserved")
		}
		if found != nil {
			return nil, identity.Err(identity.Conflict, "ambiguous Windows route snapshot")
		}
		found = cloneRecord(&key)
	}
	return found, nil
}
func writeWindowsRoute(ctx context.Context, key Record, target *Record) error {
	current, err := readWindowsRoute(ctx, key)
	if err != nil {
		return err
	}
	if target != nil && current != nil {
		return nil
	}
	if target == nil && current == nil {
		return nil
	}
	r := key.WindowsRoute
	guid, err := windows.GUIDFromString("{" + string(r.InterfaceGUID) + "}")
	if err != nil {
		return err
	}
	luid, err := winipcfg.LUIDFromGUID(&guid)
	if err != nil {
		return err
	}
	iface, err := luid.Interface()
	if err != nil {
		return err
	}
	if iface.InterfaceIndex != r.Index {
		return identity.Err(identity.Conflict, "underlay interface identity changed")
	}
	prefix := netip.MustParsePrefix(r.Destination)
	next := netip.MustParseAddr(r.NextHop)
	if target == nil {
		return luid.DeleteRoute(prefix, next)
	}
	return luid.AddRoute(prefix, next, r.Metric)
}
