package hysteria

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/streamtransport/hysteria/packet"
)

type ClientConfig struct {
	TLS      *tls.Config
	Password string
	Socket   func(context.Context) (net.PacketConn, net.Addr, error)
	Settings cfg.Hysteria
}

// Manager owns exactly one compatible identity. No process-wide or
// destination-only cache exists. A new instance snapshots TLS/settings/auth.
type Manager struct {
	config  ClientConfig
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	closed  bool
	dialing chan struct{}
	current *Connection
	workers sync.WaitGroup
	once    sync.Once
}

func NewManager(ctx context.Context, c ClientConfig) (*Manager, error) {
	if !validTLS(c.TLS) || c.Socket == nil || c.Password == "" || len(c.Password) > 1024 || c.Settings.Validate() != nil || !c.Settings.ClientOnly() {
		return nil, ErrConfig
	}
	c.TLS = snapshotTLS(c.TLS)
	c.TLS.MinVersion = tls.VersionTLS13
	c.TLS.NextProtos = []string{"h3"}
	c.Settings = c.Settings.Clone()
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	return &Manager{config: c, ctx: ctx, cancel: cancel}, nil
}
func (m *Manager) ActiveConnections() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current != nil {
		return 1
	}
	return 0
}
func (m *Manager) Congestion() []CongestionState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == nil {
		return nil
	}
	return []CongestionState{m.current.Congestion()}
}
func (m *Manager) Acquire(ctx context.Context) (*Connection, error) {
	for {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return nil, net.ErrClosed
		}
		if c := m.current; c != nil && c.Context().Err() == nil {
			m.mu.Unlock()
			return c, nil
		}
		if wait := m.dialing; wait != nil {
			m.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-m.ctx.Done():
				return nil, net.ErrClosed
			}
		}
		wait := make(chan struct{})
		m.dialing = wait
		m.workers.Add(1)
		m.mu.Unlock()
		dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		stop := context.AfterFunc(m.ctx, cancel)
		c, e := dial(dialCtx, m.config)
		stop()
		cancel()
		m.mu.Lock()
		if e == nil && (m.closed || ctx.Err() != nil) {
			if ctx.Err() != nil {
				e = ctx.Err()
			} else {
				e = net.ErrClosed
			}
		}
		if e == nil {
			m.current = c
			m.workers.Add(1)
			go m.watch(c)
		}
		if e != nil && c != nil {
			c.Close()
		}
		m.dialing = nil
		close(wait)
		m.mu.Unlock()
		m.workers.Done()
		return c, e
	}
}
func (m *Manager) watch(c *Connection) {
	defer m.workers.Done()
	select {
	case <-c.Context().Done():
	case <-m.ctx.Done():
	}
	c.Close()
	m.mu.Lock()
	if m.current == c {
		m.current = nil
	}
	m.mu.Unlock()
}
func (m *Manager) Close() {
	m.once.Do(func() { m.mu.Lock(); m.closed = true; m.mu.Unlock(); m.cancel(); m.workers.Wait() })
}
func dial(ctx context.Context, config ClientConfig) (*Connection, error) {
	socket, address, e := config.Socket(ctx)
	packetConn := socket
	if e != nil {
		return nil, e
	}
	if packetConn == nil || address == nil {
		if packetConn != nil {
			_ = packetConn.Close()
		}
		return nil, ErrConfig
	}
	socket = packet.Own(socket)
	packetConn, address, e = packet.Hop(socket, address, config.Settings.UDP)
	if e != nil {
		_ = socket.Close()
		return nil, e
	}
	before := packetConn
	packetConn, e = packet.Wrap(packetConn, config.Settings.Obfs)
	if e != nil {
		_ = before.Close()
		return nil, e
	}
	tr := &quic.Transport{Conn: packetConn}
	var q *quic.Conn
	qc := packetCarrier(config.Settings)
	qc.AssumePeerMaxDatagramFrameSize = 0
	qc.OmitMaxDatagramFrameSize = true
	control := &http3.Transport{TLSClientConfig: config.TLS.Clone(), QUICConfig: qc}
	var socketOnce sync.Once
	closeSocket := func() { socketOnce.Do(func() { _ = packetConn.Close() }) }
	release := func() { _ = control.Close(); _ = tr.Close(); closeSocket() }
	failed := true
	defer func() {
		if failed {
			if q != nil {
				_ = q.CloseWithError(0x100, "")
			}
			release()
		}
	}()
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { closeSocket(); close(interrupted) })
	watchStopped := false
	defer func() {
		if !watchStopped && !stop() {
			<-interrupted
		}
	}()
	q, e = tr.DialEarly(ctx, address, config.TLS.Clone(), qc)
	if e != nil {
		return nil, e
	}
	h3 := control.NewClientConn(q)
	req := (&http.Request{Method: http.MethodPost, URL: &url.URL{Scheme: "https", Host: "hysteria", Path: "/auth"}, Header: make(http.Header)}).WithContext(ctx)
	req.Header.Set("Hysteria-Auth", config.Password)
	req.Header.Set("Hysteria-CC-RX", receiveRate(config.Settings.QUIC, false))
	pad, e := padding()
	if e != nil {
		return nil, e
	}
	req.Header.Set("Hysteria-Padding", pad)
	resp, e := h3.RoundTrip(req)
	if e != nil {
		return nil, e
	}
	_ = resp.Body.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if resp.StatusCode != 233 || q == nil {
		return nil, ErrAuth
	}
	selected, e := chooseCongestion(config.Settings.QUIC, resp.Header.Get("Hysteria-CC-RX"), false)
	if e != nil {
		return nil, e
	}
	udp := resp.Header.Get("Hysteria-UDP")
	if udp != "true" && udp != "false" {
		return nil, ErrAuth
	}
	if !stop() {
		<-interrupted
		watchStopped = true
		return nil, ctx.Err()
	}
	watchStopped = true
	c := newConnection(q, release)
	c.congestion = selected
	c.controller = installCongestion(q, selected)
	c.UDP = udp == "true"
	c.admitted.Store(true)
	c.startDatagrams()
	failed = false
	return c, nil
}
