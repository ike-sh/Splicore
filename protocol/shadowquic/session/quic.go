//go:build with_quic

package session

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	quic "github.com/metacubex/jls-quic-go"
	tls "github.com/metacubex/jls-tls"
)

func Enabled() bool { return true }
func quicConfig(l Limits, server bool) *quic.Config {
	l = l.Defaults()
	streams := int64(-1)
	if server {
		streams = int64(l.MaxStreams)
	}
	return &quic.Config{Versions: []quic.Version{quic.Version1}, EnableDatagrams: true, MaxIncomingStreams: streams, MaxIncomingUniStreams: int64(l.MaxFlows), HandshakeIdleTimeout: l.Handshake(), MaxIdleTimeout: time.Duration(l.IdleSeconds) * time.Second, KeepAlivePeriod: time.Duration(l.KeepAliveSeconds) * time.Second, InitialStreamReceiveWindow: 128 << 10, MaxStreamReceiveWindow: 1 << 20, InitialConnectionReceiveWindow: 1 << 20, MaxConnectionReceiveWindow: 4 << 20}
}

type Client struct {
	mu        sync.Mutex
	gate      chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closed    bool
	config    ClientConfig
	current   *connection
	transport *quic.Transport
	socket    net.PacketConn
}

func NewClient(c ClientConfig) (*Client, error) {
	if c.Socket == nil || c.ServerName == "" || c.User.Username == "" || c.User.Password == "" || c.Limits.Validate() != nil {
		return nil, ErrProtocol
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{config: c, ctx: ctx, cancel: cancel, gate: make(chan struct{}, 1)}, nil
}

func (c *Client) begin(ctx context.Context) (context.Context, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, nil, net.ErrClosed
	}
	c.wg.Add(1)
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	return ctx, func() { stop(); cancel(); c.wg.Done() }, nil
}

func (c *Client) session(ctx context.Context) (*connection, error) {
	select {
	case c.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-c.gate }()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	current, transport, socket := c.current, c.transport, c.socket
	c.mu.Unlock()
	if current != nil && current.conn.Context().Err() == nil {
		return current, nil
	}
	if current != nil {
		current.close()
	}
	if transport != nil {
		_ = transport.Close()
	}
	if socket != nil {
		_ = socket.Close()
	}
	ctx, cancel := context.WithTimeout(ctx, c.config.Limits.Handshake())
	defer cancel()
	socket, remote, err := c.config.Socket(ctx)
	if err != nil {
		return nil, err
	}
	transport = &quic.Transport{Conn: socket}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = transport.Close()
		_ = socket.Close()
		return nil, net.ErrClosed
	}
	c.transport, c.socket, c.current = transport, socket, nil
	c.mu.Unlock()
	tc := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: c.config.ServerName, NextProtos: []string{"h3"}, SessionTicketsDisabled: true, JLSConfig: &tls.JLSConfig{Enable: true, User: tls.JLSUser{Username: c.config.User.Username, Password: c.config.User.Password}}}
	q, err := transport.Dial(ctx, remote, tc, quicConfig(c.config.Limits, false))
	if err != nil {
		_ = transport.Close()
		_ = socket.Close()
		return nil, err
	}
	state := q.ConnectionState().TLS.JLS
	if state.Status != tls.JLSAuthenticated || state.User != c.config.User.Username {
		_ = q.CloseWithError(0, "")
		_ = transport.Close()
		_ = socket.Close()
		return nil, ErrAuth
	}
	s := newConnection(q, c.config.Limits)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		s.close()
		_ = transport.Close()
		_ = socket.Close()
		return nil, net.ErrClosed
	}
	c.current = s
	c.mu.Unlock()
	return s, nil
}

func (c *Client) Open(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
	ctx, done, err := c.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	header, err := command(connect, dst)
	if err != nil {
		return nil, err
	}
	s, err := c.session(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = stream.Close() })
	_ = stream.SetWriteDeadline(time.Now().Add(c.config.Limits.Handshake()))
	_, err = stream.Write(header)
	if !stop() || err != nil || ctx.Err() != nil {
		_ = stream.Close()
		if err == nil {
			err = ctx.Err()
		}
		if err == nil {
			err = net.ErrClosed
		}
		return nil, err
	}
	_ = stream.SetWriteDeadline(time.Time{})
	return stream, nil
}

func (c *Client) OpenPacket(ctx context.Context, dst access.Endpoint) (net.PacketConn, error) {
	ctx, done, err := c.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if dst.Validate() != nil {
		return nil, ErrProtocol
	}
	s, err := c.session(ctx)
	if err != nil {
		return nil, err
	}
	if !c.config.UDPOverStream && !s.conn.ConnectionState().SupportsDatagrams.Remote {
		return nil, ErrProtocol
	}
	ctrl, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = ctrl.Close() })
	cmd := byte(associate)
	if c.config.UDPOverStream {
		cmd = associateStream
	}
	header, _ := command(cmd, access.Endpoint{Host: "0.0.0.0"})
	_ = ctrl.SetWriteDeadline(time.Now().Add(c.config.Limits.Handshake()))
	_, err = ctrl.Write(header)
	if !stop() || err != nil || ctx.Err() != nil {
		_ = ctrl.Close()
		if err == nil {
			err = ctx.Err()
		}
		if err == nil {
			err = net.ErrClosed
		}
		return nil, err
	}
	_ = ctrl.SetWriteDeadline(time.Time{})
	p, err := s.packetMode(ctrl, &dst, c.config.UDPOverStream)
	if err != nil {
		_ = ctrl.Close()
		return nil, err
	}
	return p, nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	c.cancel()
	s, tr, socket := c.current, c.transport, c.socket
	c.mu.Unlock()
	if s != nil {
		s.close()
	}
	if tr != nil {
		_ = tr.Close()
	}
	if socket != nil {
		_ = socket.Close()
	}
	c.wg.Wait()
	return nil
}

type Server struct {
	mu           sync.Mutex
	ctx          context.Context
	cancel       context.CancelFunc
	listener     *quic.Listener
	transport    *quic.Transport
	packet       net.PacketConn
	config       ServerConfig
	users        map[string]string
	connections  map[*quic.Conn]bool
	closed       bool
	shutdownOnce sync.Once
	wg           sync.WaitGroup
}

func camouflageCertificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	k, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer clear(k)
	return tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}))
}

func NewServer(parent context.Context, packet net.PacketConn, c ServerConfig) (*Server, error) {
	if packet == nil || c.ServerName == "" || c.Camouflage == "" || c.PacketDialer == nil || c.Authorize == nil || c.TCP == nil || c.UDP == nil || c.Limits.Validate() != nil || len(c.Users) > 128 {
		return nil, ErrProtocol
	}
	cert, err := camouflageCertificate()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	s := &Server{ctx: ctx, cancel: cancel, packet: packet, config: c, users: map[string]string{}, connections: map[*quic.Conn]bool{}}
	tc := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}, SessionTicketsDisabled: true, JLSConfig: &tls.JLSConfig{Enable: true, ServerName: c.ServerName}}
	for _, u := range c.Users {
		if u.Username == "" || u.Password == "" || u.ID == "" || s.users[u.Username] != "" {
			cancel()
			return nil, ErrProtocol
		}
		s.users[u.Username] = u.ID
		tc.JLSConfig.Users = append(tc.JLSConfig.Users, tls.JLSUser{Username: u.Username, Password: u.Password})
	}
	qc := quicConfig(c.Limits, true)
	qc.JLSConfig = &quic.JLSConfig{UpstreamAddr: c.Camouflage, RateLimit: 1 << 20, PacketDialer: c.PacketDialer}
	s.transport = &quic.Transport{Conn: packet}
	s.listener, err = s.transport.Listen(tc, qc)
	if err != nil {
		cancel()
		_ = s.transport.Close()
		return nil, err
	}
	s.wg.Add(2)
	go s.accept()
	go func() { defer s.wg.Done(); <-s.ctx.Done(); s.shutdown() }()
	return s, nil
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		q, err := s.listener.Accept(s.ctx)
		if err != nil {
			return
		}
		state := q.ConnectionState().TLS.JLS
		id := s.users[state.User]
		s.mu.Lock()
		accepted := !s.closed && len(s.connections) < s.config.Limits.Defaults().MaxConnections && state.Status == tls.JLSAuthenticated && id != "" && s.config.Authorize(id)
		if accepted {
			s.connections[q] = true
			s.wg.Add(1)
		}
		s.mu.Unlock()
		if !accepted {
			_ = q.CloseWithError(0, "")
			continue
		}
		go s.serve(q, id)
	}
}

func (s *Server) serve(q *quic.Conn, id string) {
	defer s.wg.Done()
	defer func() { s.mu.Lock(); delete(s.connections, q); s.mu.Unlock() }()
	c := newConnection(q, s.config.Limits)
	var streams sync.WaitGroup
	defer streams.Wait()
	defer c.close()
	for {
		st, err := q.AcceptStream(q.Context())
		if err != nil {
			return
		}
		streams.Go(func() {
			stream := &stream{Stream: st, conn: q}
			defer stream.Close()
			_ = stream.SetReadDeadline(time.Now().Add(s.config.Limits.Handshake()))
			cmd, dst, err := readCommand(stream)
			if err != nil || !s.config.Authorize(id) {
				return
			}
			_ = stream.SetReadDeadline(time.Time{})
			if cmd != connect && (dst.Port != 0 || net.ParseIP(dst.Host) == nil || !net.ParseIP(dst.Host).IsUnspecified()) {
				return
			}
			if cmd == connect {
				_ = s.config.TCP(q.Context(), id, stream, dst)
				return
			}
			p, err := c.packetMode(stream, nil, cmd == associateStream)
			if err != nil {
				return
			}
			defer p.Close()
			_ = s.config.UDP(q.Context(), id, p)
		})
	}
}

func (s *Server) shutdown() {
	s.shutdownOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.cancel()
		all := make([]*quic.Conn, 0, len(s.connections))
		for q := range s.connections {
			all = append(all, q)
		}
		s.mu.Unlock()
		_ = s.listener.Close()
		for _, q := range all {
			_ = q.CloseWithError(0, "")
		}
		_ = s.transport.Close()
		_ = s.packet.Close()
	})
}

func (s *Server) Close(ctx context.Context) error {
	s.shutdown()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
