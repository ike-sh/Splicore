package hostnetwork

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/sagernet/netlink"
	"github.com/sagernet/netlink/nl"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-tun"
	"golang.org/x/sys/unix"
)

const SocketMark uint32 = 0x534c0001

type Platform struct {
	mu      sync.Mutex
	devices map[string]tun.Tun
}

func NewPlatform() *Platform { return &Platform{devices: map[string]tun.Tun{}} }
func platformCapabilities() Capabilities {
	c := Capabilities{TUN: "experimental", AutoRoute: "implemented", Driver: "linux-tun", Privilege: "CAP_NET_ADMIN-required", SystemProxy: "unsupported", LoopProtection: "dedicated-daemon-uid-main-table"}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		c.Driver = "missing-or-inaccessible"
	}
	return c
}
func (*Platform) Scope() string {
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return ""
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(strings.TrimSpace(string(boot))) != 36 {
		return ""
	}
	return "linux:" + strings.TrimSpace(string(boot)) + ":" + ns + ":uid:" + strconv.Itoa(os.Geteuid())
}
func (p *Platform) Device(name string) (tun.Tun, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	d := p.devices[name]
	if d == nil {
		return nil, identity.Err(identity.Unavailable, "owned TUN device unavailable")
	}
	return d, nil
}
func absentLink(err error) bool {
	var missing netlink.LinkNotFoundError
	return errors.As(err, &missing) || errors.Is(err, unix.ENODEV)
}
func ipNet(prefix string) *net.IPNet {
	p := netip.MustParsePrefix(prefix)
	return &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}
func family(n int) int {
	if n == 6 {
		return netlink.FAMILY_V6
	}
	return netlink.FAMILY_V4
}
func (p *Platform) Read(ctx context.Context, key Record) (*Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := *cloneRecord(&key)
	switch key.Kind {
	case "interface", "address":
		link, err := netlink.LinkByName(key.Interface)
		if absentLink(err) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		out.Index = link.Attrs().Index
		if key.Kind == "interface" {
			if link.Type() != "tuntap" && link.Type() != "tun" {
				return nil, identity.Err(identity.Conflict, "unowned interface type collision")
			}
			out.MTU = uint32(link.Attrs().MTU)
			return &out, nil
		}
		addresses, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, err
		}
		for _, addr := range addresses {
			if addr.IPNet.String() == key.Prefix {
				return &out, nil
			}
		}
		return nil, nil
	case "route":
		all, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: key.Table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return nil, err
		}
		routes := []netlink.Route{}
		for _, r := range all {
			prefix := ""
			if r.Dst != nil {
				prefix = r.Dst.String()
			} else if r.Family == netlink.FAMILY_V6 {
				prefix = "::/0"
			} else {
				prefix = "0.0.0.0/0"
			}
			if prefix == key.Prefix {
				routes = append(routes, r)
			}
		}
		if len(routes) == 0 {
			return nil, nil
		}
		if len(routes) != 1 {
			return nil, identity.Err(identity.Conflict, "multiple routes collide with plan")
		}
		r := routes[0]
		if r.Scope != netlink.SCOPE_UNIVERSE || r.Type != unix.RTN_UNICAST && r.Type != unix.RTN_THROW || r.ILinkIndex != 0 || r.Src != nil || len(r.MultiPath) > 0 || r.Tos != 0 || r.Flags != 0 || r.MPLSDst != nil || r.NewDst != nil || r.Encap != nil || r.Via != nil || r.Realm != 0 || r.MTU != 0 || r.Window != 0 || r.Rtt != 0 || r.RttVar != 0 || r.Ssthresh != 0 || r.Cwnd != 0 || r.AdvMSS != 0 || r.Reordering != 0 || r.Hoplimit != 0 || r.InitCwnd != 0 || r.Features != 0 || r.RtoMin != 0 || r.InitRwnd != 0 || r.QuickACK != 0 || r.Congctl != "" || r.FastOpenNoCookie != 0 {
			return nil, identity.Err(identity.Conflict, "external route attributes preserved")
		}
		out.Index = r.LinkIndex
		out.Protocol = int(r.Protocol)
		out.Metric = r.Priority
		out.Throw = r.Type == unix.RTN_THROW
		out.Gateway = ""
		out.Interface = ""
		if len(r.Gw) > 0 {
			out.Gateway = r.Gw.String()
		}
		if r.LinkIndex > 0 {
			link, e := netlink.LinkByIndex(r.LinkIndex)
			if e != nil {
				return nil, e
			}
			if out.Throw {
				if link.Attrs().Flags&net.FlagLoopback == 0 {
					return nil, identity.Err(identity.Conflict, "throw route has an unexpected interface")
				}
			} else {
				out.Interface = link.Attrs().Name
			}
		}
		return &out, nil
	case "rule":
		rules, err := netlink.RuleList(family(key.Family))
		if err != nil {
			return nil, err
		}
		matching := []netlink.Rule{}
		for _, r := range rules {
			if r.Priority == key.Priority {
				matching = append(matching, r)
			}
		}
		if len(matching) == 0 {
			return nil, nil
		}
		if len(matching) != 1 {
			return nil, identity.Err(identity.Conflict, "multiple policy rules collide")
		}
		r := matching[0]
		if r.Src.IsValid() || r.Dst.IsValid() || r.Tos != 0 || r.TunID != 0 || r.Goto != -1 || r.Flow != -1 || r.IifName != "" || r.OifName != "" || r.SuppressIfgroup != -1 || r.SuppressPrefixlen != -1 || r.Dport != nil || r.Sport != nil || r.IPProto != 0 || r.Mask != -1 && !(r.Mark != 0 && uint64(r.Mask) == 0xffffffff) {
			return nil, identity.Err(identity.Conflict, "external policy rule selectors preserved")
		}
		if err = strictRuleAction(key); err != nil {
			return nil, err
		}
		out.Table = r.Table
		out.Mark = r.Mark
		out.Invert = r.Invert
		out.UID = nil
		if r.UIDRange != nil {
			if r.UIDRange.Start != r.UIDRange.End {
				return nil, identity.Err(identity.Conflict, "policy UID range collision")
			}
			uid := r.UIDRange.Start
			out.UID = &uid
		}
		return &out, nil
	case "proxy":
		return nil, identity.Err(identity.NotImplemented, "Linux desktop system proxy is unsupported by this adapter")
	default:
		return nil, os.ErrInvalid
	}
}
func (p *Platform) Write(ctx context.Context, key Record, value *Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	switch key.Kind {
	case "interface":
		p.mu.Lock()
		defer p.mu.Unlock()
		if value == nil {
			device := p.devices[key.Interface]
			if device == nil {
				return identity.Err(identity.Conflict, "stale interface is not owned by this process")
			}
			link, err := netlink.LinkByName(key.Interface)
			if err != nil || key.Index != 0 && link.Attrs().Index != key.Index {
				return identity.Err(identity.Conflict, "interface identity changed")
			}
			err = device.Close()
			delete(p.devices, key.Interface)
			return err
		}
		if _, err := netlink.LinkByName(key.Interface); err == nil {
			return identity.Err(identity.Conflict, "interface appeared before create")
		}
		device, err := tun.New(tun.Options{Name: value.Interface, MTU: value.MTU, DNSMode: tun.DNSModeDisabled, EXP_ExternalConfiguration: true})
		if err != nil {
			return identity.Err(identity.Unavailable, "TUN creation requires CAP_NET_ADMIN and device availability")
		}
		p.devices[value.Interface] = device
		return nil
	case "address":
		link, err := netlink.LinkByName(key.Interface)
		if err != nil {
			return err
		}
		if key.Index != 0 && key.Index != link.Attrs().Index {
			return identity.Err(identity.Conflict, "address interface identity changed")
		}
		addr := &netlink.Addr{IPNet: ipNet(key.Prefix), Flags: unix.IFA_F_NODAD}
		if value == nil {
			return netlink.AddrDel(link, addr)
		}
		return netlink.AddrAdd(link, addr)
	case "route":
		r := netlink.Route{Dst: ipNet(key.Prefix), Table: key.Table, Protocol: netlink.RouteProtocol(key.Protocol), Priority: key.Metric, Scope: netlink.SCOPE_UNIVERSE}
		if key.Throw {
			r.Type = unix.RTN_THROW
		} else {
			link, err := netlink.LinkByName(key.Interface)
			if err != nil {
				return err
			}
			if key.Index != 0 && key.Index != link.Attrs().Index {
				return identity.Err(identity.Conflict, "route interface identity changed")
			}
			r.LinkIndex = link.Attrs().Index
		}
		if key.Gateway != "" {
			r.Gw = net.ParseIP(key.Gateway)
		}
		if value == nil {
			return netlink.RouteDel(&r)
		}
		return netlink.RouteAdd(&r)
	case "rule":
		r := netlink.NewRule()
		r.Family = family(key.Family)
		r.Priority = key.Priority
		r.Table = key.Table
		r.Mark = key.Mark
		r.MarkSet = key.Mark != 0
		r.Invert = key.Invert
		if key.UID != nil {
			r.UIDRange = netlink.NewRuleUIDRange(*key.UID, *key.UID)
		}
		if value == nil {
			return netlink.RuleDel(r)
		}
		return netlink.RuleAdd(r)
	default:
		return identity.Err(identity.NotImplemented, "unsupported platform mutation")
	}
}

// The pinned netlink RuleList does not populate action/type or unknown flags.
// Read them with its same public kernel API before accepting ownership equality.
func strictRuleAction(key Record) error {
	request := nl.NewNetlinkRequest(unix.RTM_GETRULE, unix.NLM_F_DUMP|unix.NLM_F_REQUEST)
	msg := nl.NewRtMsg()
	msg.Family = uint8(family(key.Family))
	request.AddData(msg)
	messages, err := request.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWRULE)
	if err != nil {
		return err
	}
	for _, raw := range messages {
		msg := nl.DeserializeRtMsg(raw)
		attrs, err := nl.ParseRouteAttr(raw[msg.Len():])
		if err != nil {
			return err
		}
		priority := -1
		for _, a := range attrs {
			if a.Attr.Type == nl.FRA_PRIORITY {
				if len(a.Value) != 4 {
					return os.ErrInvalid
				}
				priority = int(nl.NativeEndian().Uint32(a.Value))
			}
		}
		if priority != key.Priority {
			continue
		}
		expectedFlags := uint32(0)
		if key.Invert {
			expectedFlags = 2
		}
		if msg.Type != 1 || msg.Flags != expectedFlags {
			return identity.Err(identity.Conflict, "external policy rule action preserved")
		}
		for _, a := range attrs {
			switch a.Attr.Type {
			case unix.RTA_TABLE, nl.FRA_PRIORITY, nl.FRA_UID_RANGE, nl.FRA_FWMARK, nl.FRA_FWMASK:
			default:
				if (a.Attr.Type == nl.FRA_SUPPRESS_PREFIXLEN || a.Attr.Type == nl.FRA_SUPPRESS_IFGROUP) && len(a.Value) == 4 && nl.NativeEndian().Uint32(a.Value) == 0xffffffff {
					continue
				}
				if a.Attr.Type == 18 && len(a.Value) == 0 {
					continue
				}
				// Linux adds FRA_PROTOCOL=21 with value zero to an unlabelled rule.
				if a.Attr.Type != 21 || len(a.Value) != 1 || a.Value[0] != 0 {
					return identity.Err(identity.Conflict, "unsupported policy rule attribute "+strconv.Itoa(int(a.Attr.Type)))
				}
			}
		}
		return nil
	}
	return identity.Err(identity.Conflict, "policy rule changed during read")
}
func (p *Platform) capturePlan(ctx context.Context, t client.TUNSettings, plan *Plan) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	allRoutes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{}, 0)
	if err != nil {
		return err
	}
	used := map[int]bool{}
	usedTables := map[int]bool{}
	for _, r := range allRoutes {
		usedTables[r.Table] = true
	}
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, e := netlink.RuleList(fam)
		if e != nil {
			return e
		}
		for _, r := range rules {
			used[r.Priority] = true
			usedTables[r.Table] = true
		}
	}
	table := 24000
	for ; table < 25000 && usedTables[table]; table++ {
	}
	if table == 25000 {
		return identity.Err(identity.Unavailable, "no unused policy routing table")
	}
	priority := 10000
	for ; priority < 11000; priority += 3 {
		if !used[priority] && !used[priority+1] && !used[priority+2] {
			break
		}
	}
	if priority >= 11000 {
		return identity.Err(identity.Unavailable, "no unused routing rule priorities")
	}
	families := []int{}
	for _, raw := range t.Addresses {
		prefix := netip.MustParsePrefix(raw)
		if prefix.Addr().Is4() {
			families = append(families, 4)
		} else {
			families = append(families, 6)
		}
	}
	includes := append([]string(nil), t.Include...)
	if len(includes) == 0 {
		for _, f := range families {
			if f == 4 {
				includes = append(includes, "0.0.0.0/0")
			} else {
				includes = append(includes, "::/0")
			}
		}
	}
	for _, raw := range plan.Bypass {
		plan.Records = append(plan.Records, Record{Kind: "route", Prefix: raw, Table: table, Protocol: 198, Metric: 100, Throw: true})
	}
	for _, raw := range includes {
		if slices.Contains(plan.Bypass, raw) {
			return identity.Err(identity.Conflict, "capture route equals bypass route")
		}
		plan.Records = append(plan.Records, Record{Kind: "route", Interface: t.Interface, Prefix: raw, Table: table, Protocol: 198, Metric: 100})
	}
	uid := uint32(os.Geteuid())
	for _, f := range families {
		// This dedicated process user rule also protects inherited server and Xray
		// sockets, including future endpoint IPs. Applications under this UID bypass.
		plan.Records = append(plan.Records, Record{Kind: "rule", Family: f, Priority: priority, Table: 254, UID: &uid}, Record{Kind: "rule", Family: f, Priority: priority + 1, Table: 254, Mark: SocketMark}, Record{Kind: "rule", Family: f, Priority: priority + 2, Table: table})
	}
	return nil
}
