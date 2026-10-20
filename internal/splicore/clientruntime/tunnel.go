package clientruntime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/engine/sniff"
	"github.com/ike-sh/Splicore/internal/splicore/networkruntime"
)

type tunnelCounter struct {
	accepted, allowed, denied, timeout, malformed, limit, noName, truncated atomic.Int64
}
type TunnelStats struct {
	Accepted  int64 `json:"accepted,string"`
	Allowed   int64 `json:"allowed,string"`
	Denied    int64 `json:"denied,string"`
	Timeout   int64 `json:"sniff_timeout,string"`
	Malformed int64 `json:"malformed_tls,string"`
	Limit     int64 `json:"sniff_limit,string"`
	NoName    int64 `json:"no_visible_sni,string"`
	Truncated int64 `json:"truncated,string"`
}
type TunnelObservation struct {
	ID    identity.ID `json:"id"`
	Stats TunnelStats `json:"stats"`
}

func (c *tunnelCounter) stats() TunnelStats {
	return TunnelStats{c.accepted.Load(), c.allowed.Load(), c.denied.Load(), c.timeout.Load(), c.malformed.Load(), c.limit.Load(), c.noName.Load(), c.truncated.Load()}
}

func (m *Manager) serveTunnel(ctx context.Context, s *session, gen *snapshot) {
	var inbound client.LocalInbound
	for _, i := range gen.state.LocalInbounds {
		if i.ID == s.inbound {
			inbound = i
			break
		}
	}
	if inbound.Kind != "tunnel" || inbound.Tunnel == nil {
		return
	}
	c := &gen.inCounters[s.inbound].guard
	c.accepted.Add(1)
	deny := func() { c.denied.Add(1); m.proxyFailure(s, gen) }
	if s.local.SetReadDeadline(time.Now().Add(sniff.Timeout)) != nil {
		deny()
		return
	}
	metadata, prefix, err := sniff.TLS(s.local)
	if err != nil {
		var timeout net.Error
		switch {
		case errors.As(err, &timeout) && timeout.Timeout():
			c.timeout.Add(1)
		case errors.Is(err, sniff.ErrLimit):
			c.limit.Add(1)
		case errors.Is(err, sniff.ErrNoName):
			c.noName.Add(1)
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			c.truncated.Add(1)
		default:
			c.malformed.Add(1)
		}
		deny()
		return
	}
	if ctx.Err() != nil || s.local.SetReadDeadline(time.Time{}) != nil {
		deny()
		return
	}
	target := inbound.Tunnel.Target
	q := networkruntime.Query{Port: target.Port, Network: "tcp", LocalInbound: s.inbound, SniffedProtocol: metadata.Protocol, SniffedDomain: metadata.Domain}
	if ip, e := netip.ParseAddr(target.Host); e == nil {
		q.IP = ip
	} else {
		q.Domain = target.Host
	}
	// Never resolve the sniffed name. A missing explicit matching allow is closed,
	// independently of the ordinary profile's final/default outbound.
	selected, err := gen.network.Explain(q, P.Action{Kind: P.Reject}, true, nil)
	if err != nil || selected.Rule == "" || selected.Selected != (P.Action{Kind: P.Direct}) {
		deny()
		return
	}
	c.allowed.Add(1)
	// Resolve the configured target only after admission, using the same Core DNS
	// authority as ordinary streams. Sniffed SNI remains routing metadata only.
	target, err = resolveTarget(ctx, gen, target)
	if err != nil {
		m.proxyFailure(s, gen)
		return
	}
	// Replay exactly once through the ordinary native outbound.
	m.serveSelectedStream(ctx, s, gen, selected, target, io.MultiReader(bytes.NewReader(prefix), s.local), func(byte) { m.proxyFailure(s, gen) }, func() error { return nil })
}
