package clientruntime

import (
	"context"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
)

type retirementFactory struct{ built []*retirementDialer }

func (*retirementFactory) Capability() ports.OutboundCapability {
	return ports.OutboundCapability{Protocol: "snell", Engine: "native", TCP: true}
}
func (*retirementFactory) Validate(client.RemoteNode, access.Credential) error { return nil }
func (f *retirementFactory) Build(context.Context, client.RemoteNode, access.Credential) (ports.ClientDialer, error) {
	d := &retirementDialer{closed: make(chan int64, 1)}
	f.built = append(f.built, d)
	return d, nil
}

type retirementDialer struct {
	connections atomic.Int64
	closed      chan int64
}

func (d *retirementDialer) DialContext(ctx context.Context, e access.Endpoint) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port))))
	if err != nil {
		return nil, err
	}
	d.connections.Add(1)
	return &retirementConn{Conn: c, owner: d}, nil
}
func (d *retirementDialer) Close() error {
	d.closed <- d.connections.Load()
	return nil
}

type retirementConn struct {
	net.Conn
	owner *retirementDialer
	once  sync.Once
}

func (c *retirementConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.owner.connections.Add(-1) })
	return err
}
func (c *retirementConn) CloseWrite() error { return c.Conn.(*net.TCPConn).CloseWrite() }

// Closing a socket can return resources to its adapter/pool. A retired adapter
// must outlive that final socket Close, not merely the two payload-copy workers.
func TestRetiredGenerationClosesAfterSessionConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	done := make(chan error, 1)
	go func() {
		c, e := echo.Accept()
		if e == nil {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			_, e = io.Copy(c, c)
		}
		done <- e
	}()
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(local.Addr().(*net.TCPAddr).Port)
	local.Close()
	nid, _ := identity.NewID()
	cid, _ := identity.NewID()
	oid, _ := identity.NewID()
	lid, _ := identity.NewID()
	state := client.Empty()
	state.Nodes = []client.RemoteNode{{ID: nid, Name: "synthetic", Protocol: access.ProtocolKey{Protocol: "snell", WireVersion: "6", FeatureProfile: "base"}, Endpoint: access.Endpoint{Host: "127.0.0.1", Port: 1}, CredentialID: cid, Transport: client.Transport{Kind: "tcp"}, Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: []byte(`{"version":6}`)}}}
	state.Outbounds = append(state.Outbounds, client.Outbound{ID: oid, Name: "synthetic", Kind: "proxy", NodeID: &nid, Engine: "native"})
	state.Route.DefaultOutbound = oid
	state.LocalInbounds = []client.LocalInbound{{ID: lid, Name: "local", Kind: "socks5", Listen: access.Endpoint{Host: "127.0.0.1", Port: port}}}
	f := &retirementFactory{}
	factories, err := registry.NewOutbounds(f)
	if err != nil {
		t.Fatal(err)
	}
	m := New()
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := m.Close(cleanup); err != nil {
			t.Error(err)
		}
	}()
	p, err := m.Prepare(ctx, state, nil, factories)
	if err != nil {
		t.Fatal(err)
	}
	p.Activate()
	held, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	_ = held.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = socks.Handshake(held, socks.Connect, testfixture.Endpoint((echo.Addr()).String()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := held.Write([]byte("held")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(held, b); err != nil || string(b) != "held" {
		t.Fatal("echo", err)
	}
	state.Route.DefaultOutbound = client.Direct
	state.Outbounds = state.Outbounds[:1]
	p, err = m.Prepare(ctx, state, nil, factories)
	if err != nil {
		t.Fatal(err)
	}
	p.Activate()
	select {
	case <-f.built[0].closed:
		t.Fatal("adapter retired while session held")
	default:
	}
	held.Close()
	if err := m.WaitIdle(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case active := <-f.built[0].closed:
		if active != 0 {
			t.Fatalf("retired adapter closed with %d unclosed connections", active)
		}
	case <-ctx.Done():
		t.Fatal("retired adapter was not closed")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
