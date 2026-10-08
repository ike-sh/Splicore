package native

import (
	"bufio"
	"context"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientio"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	httpproxy "github.com/ike-sh/Splicore/internal/splicore/protocol/http"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks5"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

type SOCKS5OutboundFactory struct{}
type HTTPOutboundFactory struct{}

func (SOCKS5OutboundFactory) Capability() ports.OutboundCapability {
	return clientconfig.Capability("socks5", false, false, false)
}
func (HTTPOutboundFactory) Capability() ports.OutboundCapability {
	c := clientconfig.Capability("http", false, false, false)
	c.UDP = false
	c.UDPDomainResolution = "unsupported"
	return c
}
func (SOCKS5OutboundFactory) Validate(n client.RemoteNode, c access.Credential) error {
	return proxy.Validate("socks5", n, c)
}
func (HTTPOutboundFactory) Validate(n client.RemoteNode, c access.Credential) error {
	return proxy.Validate("http", n, c)
}
func (f SOCKS5OutboundFactory) Build(ctx context.Context, n client.RemoteNode, c access.Credential) (ports.ClientDialer, error) {
	return buildProxy(ctx, "socks5", n, c)
}
func (f HTTPOutboundFactory) Build(ctx context.Context, n client.RemoteNode, c access.Credential) (ports.ClientDialer, error) {
	return buildProxy(ctx, "http", n, c)
}
func buildProxy(ctx context.Context, protocol string, n client.RemoteNode, c access.Credential) (ports.ClientDialer, error) {
	if e := proxy.Validate(protocol, n, c); e != nil {
		return nil, e
	}
	d, e := underlay.DialerFrom(ctx, underlay.PurposeFrom(ctx, underlay.ProxyUnderlay))
	if e != nil {
		return nil, e
	}
	o, _ := proxy.Decode(n.Options.Data)
	p := &proxyDialer{protected: d, node: n, udp: o.UDP, owner: clientio.New()}
	if o.Auth {
		p.cred, _ = proxy.Pair(c)
	}
	return p, nil
}

type proxyDialer struct {
	protected *underlay.Dialer
	node      client.RemoteNode
	cred      *socks5.Credentials
	udp       bool
	owner     *clientio.Owner
}

func (d *proxyDialer) SupportsNetwork(network string) bool {
	return network == "tcp" || network == "udp" && d.node.Protocol.Protocol == "socks5" && d.udp
}
func (d *proxyDialer) open(ctx context.Context, target access.Endpoint, command byte) (conn net.Conn, bind access.Endpoint, err error) {
	conn, err = d.protected.DialContext(ctx, "tcp", net.JoinHostPort(d.node.Endpoint.Host, strconv.Itoa(int(d.node.Endpoint.Port))))
	if err != nil {
		return
	}
	raw := conn
	success := false
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = raw.Close(); close(interrupted) })
	defer func() {
		if !stop() {
			<-interrupted
		}
		if !success {
			_ = raw.Close()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	if t, ok := ctx.Deadline(); ok && t.Before(deadline) {
		deadline = t
	}
	_ = raw.SetDeadline(deadline)
	if d.node.Protocol.Protocol == "http" {
		var r *bufio.Reader
		r, err = httpproxy.Connect(raw, target, d.cred)
		if err == nil {
			conn = &proxyStream{Conn: raw, reader: r}
		}
	} else {
		bind, err = socks5.ClientHandshake(raw, command, target, d.cred)
	}
	if err != nil {
		return
	}
	if ctx.Err() != nil {
		err = ctx.Err()
		return
	}
	_ = raw.SetDeadline(time.Time{})
	success = true
	return
}
func (d *proxyDialer) DialContext(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
	if dst.Validate() != nil {
		return nil, proxy.Invalid()
	}
	ctx, done, e := d.owner.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer done()
	c, _, e := d.open(ctx, dst, socks5.Connect)
	if e != nil {
		return nil, e
	}
	return d.owner.Conn(c)
}
func (d *proxyDialer) ListenPacket(ctx context.Context, dst access.Endpoint) (net.PacketConn, error) {
	if !d.SupportsNetwork("udp") {
		return nil, identity.Err(identity.NotImplemented, "proxy outbound UDP unavailable")
	}
	if dst.Validate() != nil {
		return nil, proxy.Invalid()
	}
	ctx, done, e := d.owner.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer done()
	control, bind, e := d.open(ctx, access.Endpoint{Host: "0.0.0.0"}, socks5.UDPAssociate)
	if e != nil {
		return nil, e
	}
	success := false
	defer func() {
		if !success {
			_ = control.Close()
		}
	}()
	if bind.Port == 0 {
		return nil, proxy.Invalid()
	}
	ip := net.ParseIP(bind.Host)
	if ip != nil && ip.IsUnspecified() {
		host, _, err := net.SplitHostPort(control.RemoteAddr().String())
		if err != nil {
			return nil, proxy.Invalid()
		}
		bind.Host = host
	}
	// Respect explicit relay addresses; every distinct UDP socket uses the same
	// protected underlay dialer, including when its IP differs from the TCP peer.
	udp, e := d.protected.DialContext(ctx, "udp", net.JoinHostPort(bind.Host, strconv.Itoa(int(bind.Port))))
	if e != nil {
		return nil, e
	}
	p := &socksPacket{control: control, udp: udp, done: make(chan struct{}), registered: make(chan struct{})}
	go p.watch()
	release, e := d.owner.Track(p)
	if e != nil {
		p.release = func() {}
		close(p.registered)
		_ = p.Close()
		return nil, e
	}
	p.release = release
	close(p.registered)
	success = true
	return p, nil
}
func (d *proxyDialer) Close() error { d.owner.Close(); return nil }

type proxyStream struct {
	net.Conn
	reader *bufio.Reader
}

func (c *proxyStream) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *proxyStream) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return c.Conn.Close()
}

// A composite association owns both sockets and exactly one joined control
// watcher. Control EOF is terminal and autonomously unregisters this owner.
type socksPacket struct {
	control, udp     net.Conn
	once             sync.Once
	done, registered chan struct{}
	release          func()
}

func (p *socksPacket) terminate() { p.once.Do(func() { _ = p.control.Close(); _ = p.udp.Close() }) }
func (p *socksPacket) watch() {
	_, _ = io.Copy(io.Discard, p.control)
	p.terminate()
	<-p.registered
	p.release()
	close(p.done)
}
func (p *socksPacket) Close() error                       { p.terminate(); <-p.done; return nil }
func (p *socksPacket) LocalAddr() net.Addr                { return p.udp.LocalAddr() }
func (p *socksPacket) SetDeadline(t time.Time) error      { return p.udp.SetDeadline(t) }
func (p *socksPacket) SetReadDeadline(t time.Time) error  { return p.udp.SetReadDeadline(t) }
func (p *socksPacket) SetWriteDeadline(t time.Time) error { return p.udp.SetWriteDeadline(t) }
func (p *socksPacket) WriteTo(b []byte, a net.Addr) (int, error) {
	dst, e := netaddr.From(a)
	if e != nil {
		return 0, e
	}
	frame, e := socks5.EncodePacket(dst, b)
	if e != nil {
		return 0, e
	}
	n, e := p.udp.Write(frame)
	if e != nil {
		if n > 0 {
			p.terminate()
		}
		return 0, e
	}
	if n != len(frame) {
		p.terminate()
		return 0, io.ErrShortWrite
	}
	return len(b), nil
}
func (p *socksPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	frame := make([]byte, socks5.MaxPacket+1)
	for {
		n, e := p.udp.Read(frame)
		if e != nil {
			return 0, nil, e
		}
		dst, data, e := socks5.ParsePacket(frame[:n])
		if e != nil {
			continue
		}
		return copy(b, data), netaddr.UDP(dst), nil
	}
}
