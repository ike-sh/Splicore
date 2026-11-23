package backend

import (
	"context"
	"crypto/tls"
	"errors"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

type ClientConfig struct {
	Mode, Proxy, Username, Password, Padding   string
	TLS                                        *tls.Config
	DialTCP                                    func(context.Context, string, string) (net.Conn, error)
	PacketSocket                               func(context.Context) (net.PacketConn, net.Addr, error)
	Headers                                    http.Header
	MaxConnections, MaxStreams                 int
	ConnectTimeout, TunnelTimeout, IdleTimeout time.Duration
}
type connection interface {
	open(context.Context, string, http.Header) (net.Conn, bool, error)
	alive() bool
	close() error
}
type poolSlot struct {
	conn        connection
	born        time.Time
	active      int
	retired     bool
	streams     map[*pooledStream]bool
	dialing     chan struct{}
	idleTimer   *time.Timer
	retireTimer *time.Timer
}
type Client struct {
	config     ClientConfig
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	slots      []*poolSlot
	retired    map[*poolSlot]bool
	capacity   chan struct{}
	closed     bool
	connecting sync.WaitGroup
	watchers   sync.WaitGroup
}

func NewClient(config ClientConfig) (*Client, error) {
	if config.Mode != "https" && config.Mode != "quic" || config.TLS == nil || config.TLS.InsecureSkipVerify || ValidateHeaders(config.Headers) != nil {
		return nil, ErrProtocol
	}
	if config.Mode == "quic" && !H3Enabled() {
		return nil, errors.New("Naive HTTP/3 requires with_quic")
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = 1
	}
	if config.MaxStreams == 0 {
		config.MaxStreams = 128
	}
	if config.MaxConnections < 1 || config.MaxConnections > 4 || config.MaxStreams < 1 || config.MaxStreams > 512 {
		return nil, ErrProtocol
	}
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = 5 * time.Second
	}
	if config.TunnelTimeout == 0 {
		config.TunnelTimeout = 30 * time.Minute
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = 10 * time.Minute
	}
	if config.Padding == "" {
		config.Padding = "auto"
	}
	if config.Padding != "auto" && config.Padding != "off" && config.Padding != "enabled" {
		return nil, ErrProtocol
	}
	config.TLS = config.TLS.Clone()
	config.Headers = config.Headers.Clone()
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{config: config, ctx: ctx, cancel: cancel, slots: make([]*poolSlot, config.MaxConnections), retired: map[*poolSlot]bool{}, capacity: make(chan struct{}, config.MaxStreams)}, nil
}
func (c *Client) acquire(ctx context.Context) (*poolSlot, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, net.ErrClosed
		}
		var selected *poolSlot
		var waiting <-chan struct{}
		index := 0
		for i, slot := range c.slots {
			if slot == nil {
				index = i
				selected = nil
				waiting = nil
				break
			}
			if slot.dialing != nil {
				waiting = slot.dialing
				continue
			}
			if !slot.conn.alive() || time.Since(slot.born) >= c.config.TunnelTimeout {
				c.retireLocked(slot)
				index = i
				selected = nil
				waiting = nil
				break
			}
			if selected == nil || slot.active < selected.active {
				selected = slot
				index = i
			}
		}
		if selected != nil {
			selected.active++
			if selected.idleTimer != nil {
				selected.idleTimer.Stop()
			}
			c.mu.Unlock()
			return selected, nil
		}
		if waiting != nil {
			c.mu.Unlock()
			select {
			case <-waiting:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-c.ctx.Done():
				return nil, net.ErrClosed
			}
		}
		slot := &poolSlot{dialing: make(chan struct{}), streams: map[*pooledStream]bool{}}
		c.slots[index] = slot
		c.connecting.Add(1)
		c.mu.Unlock()
		dialCtx, cancel := context.WithTimeout(ctx, c.config.ConnectTimeout)
		stop := context.AfterFunc(c.ctx, cancel)
		var conn connection
		var err error
		if c.config.Mode == "quic" {
			conn, err = newH3Connection(dialCtx, c.ctx, c.config)
		} else {
			conn, err = newH2Connection(dialCtx, c.ctx, c.config)
		}
		stop()
		cancel()
		c.mu.Lock()
		close(slot.dialing)
		slot.dialing = nil
		if err != nil || c.closed {
			if c.slots[index] == slot {
				c.slots[index] = nil
			}
			if conn != nil {
				_ = conn.close()
			}
			if err == nil {
				err = net.ErrClosed
			}
			c.mu.Unlock()
			c.connecting.Done()
			return nil, err
		}
		slot.conn = conn
		slot.born = time.Now()
		slot.active = 1
		slot.retireTimer = time.AfterFunc(c.config.TunnelTimeout, func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if !c.closed {
				c.retireLocked(slot)
			}
		})
		c.mu.Unlock()
		c.connecting.Done()
		return slot, nil
	}
}

// Retirement removes a connection from admission while allowing its existing
// streams to drain with the pinned shorter idle timeout.
func (c *Client) retireLocked(slot *poolSlot) {
	if slot.retired {
		return
	}
	slot.retired = true
	if slot.retireTimer != nil {
		slot.retireTimer.Stop()
	}
	if slot.idleTimer != nil {
		slot.idleTimer.Stop()
	}
	for i, current := range c.slots {
		if current == slot {
			c.slots[i] = nil
		}
	}
	if slot.active == 0 {
		_ = slot.conn.close()
		return
	}
	c.retired[slot] = true
	for stream := range slot.streams {
		stream.setIdle(c.config.IdleTimeout / 10)
	}
}
func (c *Client) Open(ctx context.Context, authority string) (net.Conn, error) {
	return c.open(ctx, authority, true)
}
func (c *Client) open(ctx context.Context, authority string, retry bool) (net.Conn, error) {
	select {
	case c.capacity <- struct{}{}:
	default:
		return nil, ErrBusy
	}
	slot, err := c.acquire(ctx)
	if err != nil {
		<-c.capacity
		return nil, err
	}
	headers := c.config.Headers.Clone()
	if headers == nil {
		headers = http.Header{}
	}
	headers.Set("Proxy-Authorization", Authorization(c.config.Username, c.config.Password))
	if c.config.Padding != "off" {
		value, err := HeaderPadding(false)
		if err != nil {
			c.release(slot, nil)
			return nil, err
		}
		headers.Set("Padding", value)
	}
	openCtx, cancel := context.WithTimeout(ctx, c.config.ConnectTimeout)
	conn, padding, err := slot.conn.open(openCtx, authority, headers)
	cancel()
	if err != nil {
		c.release(slot, nil)
		// Reconnect once when an established connection died during CONNECT.
		// No application payload has been sent at this point.
		if retry && ctx.Err() == nil && !slot.conn.alive() {
			return c.open(ctx, authority, false)
		}
		return nil, err
	}
	if c.config.Padding == "enabled" && !padding {
		_ = conn.Close()
		c.release(slot, nil)
		return nil, ErrProtocol
	}
	if c.config.Padding == "off" && padding {
		_ = conn.Close()
		c.release(slot, nil)
		return nil, ErrProtocol
	}
	stream := &pooledStream{Conn: conn, raw: conn, client: c, slot: slot}
	if padding {
		stream.Conn = Padded(conn)
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = conn.Close()
		c.release(slot, nil)
		return nil, net.ErrClosed
	}
	slot.streams[stream] = true
	retired := slot.retired
	c.watchers.Add(1)
	c.mu.Unlock()
	go func() { defer c.watchers.Done(); <-conn.(*bodyConn).done; _ = stream.Close() }()
	if retired {
		stream.setIdle(c.config.IdleTimeout / 10)
	}
	return stream, nil
}
func (c *Client) release(slot *poolSlot, stream *pooledStream) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(slot.streams, stream)
	slot.active--
	<-c.capacity
	if slot.active == 0 {
		if slot.retired || c.closed {
			_ = slot.conn.close()
			delete(c.retired, slot)
		} else {
			slot.idleTimer = time.AfterFunc(c.config.IdleTimeout, func() {
				c.mu.Lock()
				defer c.mu.Unlock()
				if slot.active == 0 {
					c.retireLocked(slot)
				}
			})
		}
	}
}
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.cancel()
	all := map[*poolSlot]bool{}
	for _, slot := range c.slots {
		if slot != nil {
			all[slot] = true
		}
	}
	for slot := range c.retired {
		all[slot] = true
	}
	streams := []*pooledStream{}
	for slot := range all {
		if slot.idleTimer != nil {
			slot.idleTimer.Stop()
		}
		if slot.retireTimer != nil {
			slot.retireTimer.Stop()
		}
		for stream := range slot.streams {
			streams = append(streams, stream)
		}
		if slot.conn != nil {
			_ = slot.conn.close()
		}
	}
	c.mu.Unlock()
	for _, stream := range streams {
		_ = stream.Close()
	}
	c.connecting.Wait()
	c.watchers.Wait()
	return nil
}

type pooledStream struct {
	net.Conn
	raw    net.Conn
	client *Client
	slot   *poolSlot
	once   sync.Once
}

func (s *pooledStream) Close() error {
	s.once.Do(func() { _ = s.Conn.Close(); s.client.release(s.slot, s) })
	return nil
}
func (s *pooledStream) CloseWrite() error {
	if half, ok := s.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return s.Close()
}
func (s *pooledStream) setIdle(d time.Duration) {
	if conn, ok := s.raw.(interface{ setIdle(time.Duration) }); ok {
		conn.setIdle(d)
	}
}

type h2CarrierConn struct {
	net.Conn
	failed atomic.Bool
}

func (c *h2CarrierConn) Read(p []byte) (n int, err error) {
	n, err = c.Conn.Read(p)
	if err != nil {
		c.failed.Store(true)
	}
	return
}
func (c *h2CarrierConn) Write(p []byte) (n int, err error) {
	n, err = c.Conn.Write(p)
	if err != nil {
		c.failed.Store(true)
	}
	return
}
func (c *h2CarrierConn) Close() error {
	c.failed.Store(true)
	return c.Conn.Close()
}

type h2Connection struct {
	client  *http2.ClientConn
	tcp     net.Conn
	carrier *h2CarrierConn
	ctx     context.Context
	config  ClientConfig
}

func newH2Connection(ctx, lifetime context.Context, config ClientConfig) (connection, error) {
	if config.DialTCP == nil {
		return nil, ErrProtocol
	}
	raw, err := config.DialTCP(ctx, "tcp", config.Proxy)
	if err != nil {
		return nil, err
	}
	// Cover TLS and the synchronous H2 preface/SETTINGS writes. Until the
	// connection is published in its pool slot, shutdown owns it through
	// this setup context rather than the slot's connection pointer.
	setupClosed := make(chan struct{})
	stopSetup := context.AfterFunc(ctx, func() { _ = raw.Close(); close(setupClosed) })
	var setupOnce sync.Once
	finishSetup := func() {
		setupOnce.Do(func() {
			if !stopSetup() {
				<-setupClosed
			}
		})
	}
	defer finishSetup()
	if deadline, ok := ctx.Deadline(); ok {
		if err := raw.SetDeadline(deadline); err != nil {
			_ = raw.Close()
			return nil, err
		}
	}
	tc := config.TLS.Clone()
	tc.NextProtos = []string{"h2"}
	conn := tls.Client(raw, tc)
	if err = conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		_ = conn.Close()
		return nil, ErrProtocol
	}
	transport := &http2.Transport{DisableCompression: true, StrictMaxConcurrentStreams: true, MaxHeaderListSize: MaxHeaders}
	carrier := &h2CarrierConn{Conn: conn}
	client, err := transport.NewClientConn(carrier)
	if err != nil {
		_ = carrier.Close()
		return nil, err
	}
	// Join any cancellation callback before handing ownership to the pool.
	// A successful connection must not inherit the caller's dial deadline.
	finishSetup()
	if err = ctx.Err(); err != nil {
		_ = client.Close()
		return nil, err
	}
	if err = raw.SetDeadline(time.Time{}); err != nil {
		_ = client.Close()
		return nil, err
	}
	return &h2Connection{client: client, tcp: carrier, carrier: carrier, ctx: lifetime, config: config}, nil
}
func (h *h2Connection) alive() bool {
	state := h.client.State()
	return !state.Closed && !state.Closing
}
func (h *h2Connection) close() error { _ = h.client.Close(); return h.tcp.Close() }

// A PipeWriter.Close alone also returns nil when the transport has already
// closed the request body. Order reader shutdown and local EOF acceptance.
type h2RequestBody struct {
	*io.PipeReader
	mu     sync.Mutex
	closed bool
	failed error
}

func (r *h2RequestBody) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return r.PipeReader.Close()
}

func (r *h2RequestBody) finish(w *io.PipeWriter) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed != nil {
		return r.failed
	}
	if r.closed {
		return io.ErrClosedPipe
	}
	return w.Close()
}

func h2FinishWrite(ctx context.Context, request *h2RequestBody, writer *io.PipeWriter, carrier *h2CarrierConn) func() error {
	return func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		// x/net/http2 publishes ClientConn.closed before asynchronously closing
		// request bodies. The carrier witness is committed by Read/Write/Close
		// first and avoids both that mirror lag and ClientConn.State's write lock.
		if carrier.failed.Load() {
			return net.ErrClosed
		}
		err := request.finish(writer)
		if carrier.failed.Load() {
			return net.ErrClosed
		}
		return err
	}
}

type h2ResponseBody struct {
	io.ReadCloser
	request *h2RequestBody
}

func (r h2ResponseBody) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		// HTTP/2 reset/connection failure ends this request, while a
		// normal response EOF leaves the upload independent. Record the
		// error before the read pump publishes it to the caller.
		r.request.mu.Lock()
		r.request.failed = err
		r.request.mu.Unlock()
	}
	return n, err
}

func (h *h2Connection) open(ctx context.Context, authority string, headers http.Header) (net.Conn, bool, error) {
	streamCtx, cancel := context.WithCancel(h.ctx)
	stop := untilEstablished(ctx, cancel)
	defer stop()
	pipe, writer := io.Pipe()
	reader := &h2RequestBody{PipeReader: pipe}
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Scheme: "https", Host: authority}, Host: authority,
		Header: headers, Body: reader, ContentLength: -1}
	resp, err := h.client.RoundTrip(req.WithContext(streamCtx))
	if err != nil {
		cancel()
		_ = reader.Close()
		_ = writer.Close()
		return nil, false, err
	}
	padding, err := paddingOffered(resp.Header)
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 || ctx.Err() != nil {
		cancel()
		_ = resp.Body.Close()
		_ = reader.Close()
		_ = writer.Close()
		return nil, false, ErrProtocol
	}
	stop()
	finishWrite := h2FinishWrite(streamCtx, reader, writer, h.carrier)
	body := h2ResponseBody{ReadCloser: resp.Body, request: reader}
	conn := newBodyConn(body, writer, finishWrite, func(bool) { cancel(); _ = reader.Close() }, h.tcp.LocalAddr(), h.tcp.RemoteAddr(), h.config.IdleTimeout)
	return conn, padding, nil
}
