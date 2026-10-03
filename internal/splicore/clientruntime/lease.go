package clientruntime

import (
	"context"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"net"
	"sync/atomic"
	"time"
)

// A generation owns a lease reference; sessions own generation references.
// Thus an unchanged adapter survives route changes and a changed adapter lives
// until its last TCP/UDP session has closed all borrowed sockets and workers.
type dialerLease struct {
	dialer ports.ClientDialer
	key    string
	refs   atomic.Int64
	health atomic.Pointer[passiveHealth]
}

func (l *dialerLease) failed() {
	l.health.Store(&passiveHealth{lastError: "outbound_connection_failed", at: time.Now()})
}
func (l *dialerLease) success() { l.health.Store(succeededHealth) }

func (l *dialerLease) DialContext(ctx context.Context, e access.Endpoint) (net.Conn, error) {
	return l.dialer.DialContext(ctx, e)
}
func (l *dialerLease) ListenPacket(ctx context.Context, e access.Endpoint) (net.PacketConn, error) {
	p, ok := l.dialer.(ports.ClientPacketDialer)
	if !ok {
		return nil, identity.Err(identity.NotImplemented, "outbound UDP unavailable")
	}
	return p.ListenPacket(ctx, e)
}
func (l *dialerLease) Close() error {
	if l.refs.Add(-1) == 0 {
		return l.dialer.Close()
	}
	return nil
}
func effectiveKey(o client.Outbound, n client.RemoteNode) string {
	// Labels and metadata do not alter runtime or credential ownership.
	o.Name = ""
	n.Name = ""
	n.Metadata = identity.Metadata{}
	b, _ := json.Marshal(struct {
		Outbound client.Outbound
		Node     client.RemoteNode
	}{o, n})
	return string(b)
}
