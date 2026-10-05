package native

import (
	"context"
	"net"
	"strings"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/dns/transport/mdns"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/underlay"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

// Embed the unmodified mature NetworkManager. Only its socket control is
// replaced, preserving resolver/detour semantics and the static monitor.
type protectedNetwork struct {
	adapter.NetworkManager
	dialer *underlay.Dialer
}

func (n protectedNetwork) AutoDetectInterface() bool { return true }
func (n protectedNetwork) AutoDetectInterfaceFunc() control.Func {
	return func(network, address string, r syscall.RawConn) error { return n.dialer.Control(network, address, r) }
}
func (n protectedNetwork) ProtectFunc() control.Func { return n.AutoDetectInterfaceFunc() }

func protectedContext(ctx context.Context, p underlay.Purpose) (context.Context, error) {
	d, err := underlay.DialerFrom(ctx, p)
	if err != nil {
		return nil, err
	}
	n := service.FromContext[adapter.NetworkManager](ctx)
	if n == nil {
		return nil, identity.Err(identity.Unavailable, "native network manager unavailable")
	}
	return service.ContextWith[adapter.NetworkManager](service.ExtendContext(ctx), protectedNetwork{n, d}), nil
}

type protectedOutbounds struct {
	adapter.OutboundRegistry
	purpose underlay.Purpose
}

func (r protectedOutbounds) CreateOutbound(ctx context.Context, router adapter.Router, l log.ContextLogger, tag, kind string, options any) (adapter.Outbound, error) {
	ctx, err := protectedContext(ctx, r.purpose)
	if err != nil {
		return nil, err
	}
	return r.OutboundRegistry.CreateOutbound(ctx, router, l, tag, kind, options)
}

type protectedDNS struct{ adapter.DNSTransportRegistry }

func (r protectedDNS) CreateDNSTransport(ctx context.Context, l log.ContextLogger, tag, kind string, raw any) (adapter.DNSTransport, error) {
	ctx, err := protectedContext(ctx, underlay.SystemDNS)
	if err != nil {
		return nil, err
	}
	if kind == "local" {
		o := option.LocalDNSServerOptions{}
		if raw != nil {
			o = *raw.(*option.LocalDNSServerOptions)
		}
		t, err := local.NewTransport(ctx, l, tag, o)
		if err != nil {
			return nil, err
		}
		f, err := underlay.FromContext(ctx)
		if err != nil {
			return nil, err
		}
		d, err := underlay.DialerFrom(ctx, underlay.SystemDNS)
		if err != nil {
			return nil, err
		}
		return protectedLocalDNS{t.(*local.Transport), f, d}, nil
	}
	return r.DNSTransportRegistry.CreateDNSTransport(ctx, l, tag, kind, raw)
}

// Official local transport retains its complete no-TUN behavior. With TUN,
// System address resolution cannot delegate to resolved/mDNS/Windows APIs:
// those independently create sockets outside the injected NetworkManager.
type protectedLocalDNS struct {
	*local.Transport
	f *underlay.Factory
	d *underlay.Dialer
}

func (t protectedLocalDNS) Exchange(ctx context.Context, q *mDNS.Msg) (*mDNS.Msg, error) {
	if !t.f.Required() {
		return t.Transport.Exchange(ctx, q)
	}
	if q == nil || len(q.Question) != 1 || q.Question[0].Qclass != mDNS.ClassINET {
		return nil, identity.Err(identity.Invalid, "invalid native system DNS question")
	}
	question := q.Question[0]
	if mdns.IsLocalDomain(question.Name) {
		return nil, identity.Err(identity.Unavailable, "unsafe_underlay: native mDNS protection unavailable")
	}
	network := "ip4"
	if question.Qtype == mDNS.TypeAAAA {
		network = "ip6"
	} else if question.Qtype != mDNS.TypeA {
		return nil, identity.Err(identity.Unavailable, "unsafe_underlay: unsupported system DNS question")
	}
	ips, err := t.d.LookupNetIP(ctx, network, strings.TrimSuffix(question.Name, "."))
	if err != nil {
		return nil, err
	}
	r := new(mDNS.Msg)
	r.SetReply(q)
	for _, ip := range ips {
		h := mDNS.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: mDNS.ClassINET, Ttl: 30}
		if ip.Is4() {
			r.Answer = append(r.Answer, &mDNS.A{Hdr: h, A: net.IP(ip.AsSlice())})
		} else {
			r.Answer = append(r.Answer, &mDNS.AAAA{Hdr: h, AAAA: net.IP(ip.AsSlice())})
		}
	}
	return r, nil
}

func (t protectedLocalDNS) ExchangeAsync(ctx context.Context, q *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	if !t.f.Required() {
		t.Transport.ExchangeAsync(ctx, q, callback)
		return
	}
	r, err := t.Exchange(ctx, q)
	callback(r, err)
}
