//go:build with_quic && with_utls

package application_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks"
)

// Forward every operation to the real native adapter, preserving network
// support and half-close. Only terminal transport errors are observed so the
// canonical SOCKS reply cannot hide whether DNS/proxy dialing failed earlier.
type routingObservedFactory struct {
	ports.OutboundFactory
	t *testing.T
}

func (f routingObservedFactory) Build(ctx context.Context, n client.RemoteNode, c access.Credential) (ports.ClientDialer, error) {
	d, err := f.OutboundFactory.Build(ctx, n, c)
	if err != nil {
		return nil, err
	}
	return &routingObservedDialer{ClientDialer: d, t: f.t, protocol: n.Protocol.Protocol}, nil
}

type routingObservedDialer struct {
	ports.ClientDialer
	t        *testing.T
	protocol string
}

func (d *routingObservedDialer) SupportsNetwork(network string) bool {
	if support, ok := d.ClientDialer.(ports.ClientNetworkSupport); ok {
		return support.SupportsNetwork(network)
	}
	if network == "tcp" {
		return true
	}
	_, ok := d.ClientDialer.(ports.ClientPacketDialer)
	return network == "udp" && ok
}
func (d *routingObservedDialer) DialContext(ctx context.Context, target access.Endpoint) (net.Conn, error) {
	c, err := d.ClientDialer.DialContext(ctx, target)
	if err != nil {
		d.t.Logf("routing_adapter at=%s protocol=%s target=%s:%d stage=dial cause=%T %v", time.Now().UTC().Format(time.RFC3339Nano), d.protocol, target.Host, target.Port, err, err)
		return nil, err
	}
	return &routingObservedConn{Conn: c, t: d.t, protocol: d.protocol, target: target}, nil
}
func (d *routingObservedDialer) ListenPacket(ctx context.Context, target access.Endpoint) (net.PacketConn, error) {
	p, ok := d.ClientDialer.(ports.ClientPacketDialer)
	if !ok {
		return nil, fmt.Errorf("native adapter has no UDP support")
	}
	return p.ListenPacket(ctx, target)
}

type routingObservedConn struct {
	net.Conn
	t        *testing.T
	protocol string
	target   access.Endpoint
}

func (c *routingObservedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil {
		c.t.Logf("routing_adapter at=%s protocol=%s target=%s:%d stage=read bytes=%d cause=%T %v", time.Now().UTC().Format(time.RFC3339Nano), c.protocol, c.target.Host, c.target.Port, n, err, err)
	}
	return n, err
}
func (c *routingObservedConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Conn.Close()
}

// Only this no-auth synthetic fixture is traced. Credentials and application
// payload never enter the wire trace; framing still uses the canonical helper.
type routingTraceConn struct {
	net.Conn
	t     *testing.T
	phase string
	wire  atomic.Bool
	sent  atomic.Int64
}

func (c *routingTraceConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if c.wire.Load() {
		stage := "method-selection"
		if c.sent.Load() > 3 {
			stage = "request-reply"
		}
		c.t.Logf("routing_diag at=%s phase=%s socks_stage=%s direction=server bytes=%x error=%v", time.Now().UTC().Format(time.RFC3339Nano), c.phase, stage, b[:n], err)
	}
	return n, err
}
func (c *routingTraceConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if c.wire.Load() {
		stage := "greeting"
		if c.sent.Load() >= 3 {
			stage = "request"
		}
		c.sent.Add(int64(n))
		c.t.Logf("routing_diag at=%s phase=%s socks_stage=%s direction=client bytes=%x error=%v", time.Now().UTC().Format(time.RFC3339Nano), c.phase, stage, b[:n], err)
	}
	return n, err
}
func (c *routingTraceConn) Close() error {
	err := c.Conn.Close()
	c.t.Logf("routing_diag at=%s phase=%s connection=closed error=%v", time.Now().UTC().Format(time.RFC3339Nano), c.phase, err)
	return err
}

func routingPhase(t *testing.T, s *application.Service, phase string) {
	t.Helper()
	st, err := s.ClientStatus(context.Background())
	if err != nil {
		t.Fatal("routing diagnostic status", err)
	}
	graph, err := json.Marshal(st.State.Network)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("routing_diag at=%s phase=%s revision=%d graph_sha256=%x generations=%v listener_health=%s sessions=%d dns=%+v",
		time.Now().UTC().Format(time.RFC3339Nano), phase, st.State.Revision, sha256.Sum256(graph), st.Underlay.Generations, st.Health, len(st.Sessions), st.Network.DNS)
}

func routingSOCKS(t *testing.T, s *application.Service, port uint16, target access.Endpoint, command byte, phase string) (net.Conn, access.Endpoint, error) {
	t.Helper()
	routingPhase(t, s, phase+"/before-dial")
	listener := fmt.Sprintf("127.0.0.1:%d", port)
	raw, err := net.DialTimeout("tcp", listener, 5*time.Second)
	t.Logf("routing_diag at=%s phase=%s listener=%s target=%s:%d dial_error=%v", time.Now().UTC().Format(time.RFC3339Nano), phase, listener, target.Host, target.Port, err)
	if err != nil {
		return nil, access.Endpoint{}, fmt.Errorf("%s TCP dial: %w", phase, err)
	}
	c := &routingTraceConn{Conn: raw, t: t, phase: phase}
	c.wire.Store(true)
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	bound, err := socks.Handshake(c, command, target)
	c.wire.Store(false)
	routingPhase(t, s, phase+"/after-handshake")
	if err != nil {
		_ = c.Close()
		stage := "greeting/method-selection"
		if c.sent.Load() > 3 {
			stage = "request/reply"
		}
		return nil, bound, fmt.Errorf("%s SOCKS %s (see wire bytes): %w", phase, stage, err)
	}
	return c, bound, nil
}
