package session

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ike-sh/Splicore/protocol/trusttunnel/wire"
	"golang.org/x/net/http/httpguts"
)

type State string

const (
	New         State = "NEW"
	Connecting  State = "CONNECTING"
	Ready       State = "READY"
	Degraded    State = "DEGRADED"
	Recovering  State = "RECOVERING"
	Closing     State = "CLOSING"
	ClosedState State = "CLOSED"
)

type ClientConfig struct {
	Mode                                                                                                string
	Addresses                                                                                           []string
	Username, Password, UserAgent                                                                       string
	TLS                                                                                                 *tls.Config
	DialTCP                                                                                             func(context.Context, string, string) (net.Conn, error)
	PacketSocket                                                                                        func(context.Context, string) (net.PacketConn, net.Addr, error)
	ConnectTimeout, HealthTimeout, FallbackDelay, StreamIdleTimeout, SessionIdleTimeout, UDPIdleTimeout time.Duration
	RecoveryInitial, RecoveryCap                                                                        time.Duration
	MaxStreams, MaxFlows                                                                                int
}

func (ClientConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("TrustTunnelClientConfig{[REDACTED]}"))
}
func validMode(v string) bool { return v == "http2" || v == "http3" || v == "auto" }
func normalizeClient(c ClientConfig) (ClientConfig, error) {
	if !validMode(c.Mode) || c.TLS == nil || !wire.Credentials(c.Username, c.Password) || len(c.Addresses) == 0 || len(c.Addresses) > 16 {
		return c, failure(Config, nil)
	}
	if c.Mode != "http2" && !H3Enabled() {
		return c, failure(Config, nil)
	}
	if c.Mode != "http3" && c.DialTCP == nil || c.Mode != "http2" && c.PacketSocket == nil {
		return c, failure(Config, nil)
	}
	if c.TLS.ServerName == "" {
		return c, failure(Config, nil)
	}
	c.TLS = c.TLS.Clone()
	if c.TLS.RootCAs != nil {
		c.TLS.RootCAs = c.TLS.RootCAs.Clone()
	}
	c.TLS.MinVersion = max(c.TLS.MinVersion, tls.VersionTLS12)
	seen := map[string]bool{}
	addresses := []string{}
	for _, a := range c.Addresses {
		v, e := wire.Authority(a)
		if e != nil {
			return c, failure(Config, e)
		}
		if !seen[v] {
			seen[v] = true
			addresses = append(addresses, v)
		}
	}
	c.Addresses = addresses
	if c.UserAgent == "" {
		c.UserAgent = "Splicore TrustTunnel"
	}
	if len(c.UserAgent) > 512 || !httpguts.ValidHeaderFieldValue(c.UserAgent) || strings.ContainsAny(c.UserAgent, "\x00\r\n") {
		return c, failure(Config, nil)
	}
	for _, v := range []struct {
		p *time.Duration
		d time.Duration
	}{{&c.ConnectTimeout, 30 * time.Second}, {&c.HealthTimeout, 7 * time.Second}, {&c.FallbackDelay, time.Second}, {&c.StreamIdleTimeout, 2 * time.Hour}, {&c.SessionIdleTimeout, 10 * time.Minute}, {&c.UDPIdleTimeout, 120 * time.Second}, {&c.RecoveryInitial, time.Second}, {&c.RecoveryCap, 30 * time.Second}} {
		if *v.p == 0 {
			*v.p = v.d
		}
		if *v.p < time.Millisecond || *v.p > 24*time.Hour {
			return c, failure(Config, nil)
		}
	}
	if c.RecoveryInitial > c.RecoveryCap {
		return c, failure(Config, nil)
	}
	if c.MaxStreams == 0 {
		c.MaxStreams = 256
	}
	if c.MaxFlows == 0 {
		c.MaxFlows = 256
	}
	if c.MaxStreams < 4 || c.MaxStreams > 512 || c.MaxFlows < 1 || c.MaxFlows > 4096 {
		return c, failure(Config, nil)
	}
	return c, nil
}

type clientSession struct {
	raw         connection
	ctx         context.Context
	cancel      context.CancelFunc
	mode        string
	mu          sync.Mutex
	udp         *udpMux
	udpOpening  chan struct{}
	echo        *echoMux
	echoOpening chan struct{}
	streams     map[*clientStream]bool
	lastRx      atomic.Int64
	lastUse     atomic.Int64
	check       *healthFlight
}
type healthFlight struct {
	done   chan struct{}
	cancel context.CancelFunc
	err    error
	data   bool
}

func (s *clientSession) received() {
	s.lastRx.Store(time.Now().UnixNano())
	s.mu.Lock()
	if s.check != nil {
		s.check.data = true
		s.check.cancel()
	}
	s.mu.Unlock()
}
func (s *clientSession) close() {
	s.cancel()
	_ = s.raw.close()
	s.mu.Lock()
	all := make([]*clientStream, 0, len(s.streams))
	for stream := range s.streams {
		all = append(all, stream)
	}
	s.mu.Unlock()
	for _, stream := range all {
		_ = stream.Close()
	}
}

// Client owns at most one active authenticated session and one selection race.
// Identity is immutable and instance-scoped, so credentials/trust never share a
// process-global pool. Recovery is admission-driven with a shared bounded backoff.
type Client struct {
	config   ClientConfig
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	state    State
	session  *clientSession
	dialing  chan struct{}
	terminal error
	next     time.Time
	backoff  time.Duration
	capacity chan struct{}
	workers  sync.WaitGroup
	joined   chan struct{}
}

func NewClient(c ClientConfig) (*Client, error) {
	c, e := normalizeClient(c)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	v := &Client{config: c, ctx: ctx, cancel: cancel, state: New, capacity: make(chan struct{}, c.MaxStreams), joined: make(chan struct{})}
	v.workers.Add(1)
	go v.monitor()
	return v, nil
}
func (c *Client) State() State { c.mu.Lock(); defer c.mu.Unlock(); return c.state }
func (c *Client) monitor() {
	defer c.workers.Done()
	timer := time.NewTicker(min(time.Second, c.config.SessionIdleTimeout))
	defer timer.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-timer.C:
			c.mu.Lock()
			s := c.session
			c.mu.Unlock()
			if s == nil {
				continue
			}
			if !s.raw.alive() {
				c.invalidate(s, failure(Unavailable, nil))
				continue
			}
			if time.Since(time.Unix(0, s.lastUse.Load())) >= c.config.SessionIdleTimeout {
				s.mu.Lock()
				n := len(s.streams)
				if s.udp != nil {
					s.udp.mu.Lock()
					if len(s.udp.flows) == 0 {
						n--
					}
					s.udp.mu.Unlock()
				}
				if s.echo != nil {
					s.echo.mu.Lock()
					if len(s.echo.pending) == 0 {
						n--
					}
					s.echo.mu.Unlock()
				}
				s.mu.Unlock()
				if n == 0 {
					c.invalidate(s, nil)
					continue
				}
			}
			if time.Since(time.Unix(0, s.lastRx.Load())) >= c.config.ConnectTimeout {
				ctx, cancel := context.WithTimeout(c.ctx, c.config.HealthTimeout)
				_ = c.checkSession(ctx, s)
				cancel()
			}
		}
	}
}
func (c *Client) invalidate(s *clientSession, err error) {
	c.mu.Lock()
	if c.session != s {
		c.mu.Unlock()
		return
	}
	c.session = nil
	if c.state != Closing && c.state != ClosedState {
		c.state = Degraded
		if IsCode(err, Auth) || IsCode(err, Certificate) {
			c.terminal = err
		} else if err != nil {
			if c.backoff == 0 {
				c.backoff = c.config.RecoveryInitial
			}
			c.next = time.Now().Add(c.backoff)
			c.backoff = min(c.config.RecoveryCap, time.Duration(float64(c.backoff)*1.3))
			c.state = Recovering
		}
	}
	c.mu.Unlock()
	s.close()
}
func (c *Client) acquire(ctx context.Context) (*clientSession, error) {
	for {
		c.mu.Lock()
		if c.ctx.Err() != nil {
			c.mu.Unlock()
			return nil, failure(Closed, net.ErrClosed)
		}
		if c.terminal != nil {
			e := c.terminal
			c.mu.Unlock()
			return nil, e
		}
		if s := c.session; s != nil {
			if s.ctx.Err() == nil && s.raw.alive() {
				c.mu.Unlock()
				return s, nil
			}
			c.mu.Unlock()
			c.invalidate(s, failure(Unavailable, nil))
			continue
		}
		if c.dialing != nil {
			wait := c.dialing
			c.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, failure(Closed, ctx.Err())
			case <-c.ctx.Done():
				return nil, failure(Closed, net.ErrClosed)
			}
		}
		if wait := time.Until(c.next); wait > 0 {
			c.mu.Unlock()
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil, failure(Closed, ctx.Err())
			case <-c.ctx.Done():
				timer.Stop()
				return nil, failure(Closed, net.ErrClosed)
			}
			continue
		}
		c.dialing = make(chan struct{})
		c.state = Connecting
		c.workers.Add(1)
		c.mu.Unlock()
		setup, cancel := context.WithTimeout(ctx, c.config.ConnectTimeout+c.config.HealthTimeout+c.config.FallbackDelay)
		stop := context.AfterFunc(c.ctx, cancel)
		raw, mode, e := c.selectConnection(setup)
		stop()
		cancel()
		c.mu.Lock()
		close(c.dialing)
		c.dialing = nil
		if e != nil || c.ctx.Err() != nil {
			if e == nil {
				e = failure(Closed, net.ErrClosed)
			}
			if raw != nil {
				_ = raw.close()
			}
			if c.ctx.Err() == nil {
				c.state = Recovering
				if IsCode(e, Auth) || IsCode(e, Certificate) {
					c.state = Degraded
					c.terminal = e
				} else {
					if c.backoff == 0 {
						c.backoff = c.config.RecoveryInitial
					}
					c.next = time.Now().Add(c.backoff)
					c.backoff = min(c.config.RecoveryCap, time.Duration(float64(c.backoff)*1.3))
				}
			}
			c.mu.Unlock()
			c.workers.Done()
			return nil, e
		}
		life, closeSession := context.WithCancel(c.ctx)
		s := &clientSession{raw: raw, ctx: life, cancel: closeSession, mode: mode, streams: map[*clientStream]bool{}}
		s.lastRx.Store(time.Now().UnixNano())
		s.lastUse.Store(time.Now().UnixNano())
		c.session = s
		c.state = Ready
		c.backoff = 0
		c.next = time.Time{}
		c.mu.Unlock()
		c.workers.Done()
		return s, nil
	}
}

type selectionResult struct {
	raw  connection
	mode string
	err  error
}

func (c *Client) dialMode(ctx context.Context, mode string) (connection, error) {
	var last error
	for index, a := range c.config.Addresses {
		budget := c.config.ConnectTimeout + c.config.HealthTimeout
		if deadline, ok := ctx.Deadline(); ok {
			budget = max(time.Millisecond, time.Until(deadline)/time.Duration(len(c.config.Addresses)-index))
		}
		attempt, stopAttempt := context.WithTimeout(ctx, budget)
		var raw connection
		var e error
		if mode == "http3" {
			raw, e = newH3(attempt, c.ctx, c.config, a)
		} else {
			raw, e = newH2(attempt, c.ctx, c.config, a)
		}
		if e == nil {
			check, cancel := context.WithTimeout(attempt, c.config.HealthTimeout)
			var stream net.Conn
			stream, e = raw.open(check, "_check", c.headers("_check"))
			cancel()
			if stream != nil {
				finishCheck(stream)
			}
			if e == nil {
				stopAttempt()
				return raw, nil
			}
			_ = raw.close()
		}
		stopAttempt()
		if IsCode(e, Auth) || IsCode(e, Certificate) {
			return nil, e
		}
		last = e
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}
func (c *Client) selectConnection(ctx context.Context) (connection, string, error) {
	if c.config.Mode != "auto" {
		r, e := c.dialMode(ctx, c.config.Mode)
		return r, c.config.Mode, e
	}
	race, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan selectionResult, 2)
	var wg sync.WaitGroup
	start := func(mode string) {
		wg.Add(1)
		go func() { defer wg.Done(); r, e := c.dialMode(race, mode); results <- selectionResult{r, mode, e} }()
	}
	start("http3")
	timer := time.NewTimer(c.config.FallbackDelay)
	defer timer.Stop()
	started, received := 1, 0
	var winner selectionResult
	var last error
	for received < started || started == 1 {
		select {
		case v := <-results:
			received++
			if v.err == nil {
				winner = v
				cancel()
				goto done
			}
			last = v.err
			if IsCode(v.err, Auth) || IsCode(v.err, Certificate) {
				cancel()
				goto done
			}
			if started == 1 {
				start("http2")
				started++
			}
		case <-timer.C:
			if started == 1 {
				start("http2")
				started++
			}
		case <-ctx.Done():
			last = failure(Closed, ctx.Err())
			cancel()
			goto done
		}
	}
done:
	cancel()
	wg.Wait()
	for received < started {
		v := <-results
		received++
		if v.raw != nil {
			_ = v.raw.close()
		}
	}
	if winner.raw != nil {
		return winner.raw, winner.mode, nil
	}
	return nil, "", last
}
func (c *Client) headers(authority string) http.Header {
	ua := c.config.UserAgent
	if authority == "_udp2" || authority == "_icmp" {
		ua += " " + authority
	}
	return http.Header{"User-Agent": {ua}, "Proxy-Authorization": {wire.Authorization(c.config.Username, c.config.Password)}}
}
func (c *Client) openSession(ctx context.Context, s *clientSession, authority string) (net.Conn, error) {
	select {
	case c.capacity <- struct{}{}:
	default:
		return nil, failure(Capacity, nil)
	}
	setup, cancel := context.WithTimeout(ctx, c.config.ConnectTimeout)
	stop := context.AfterFunc(s.ctx, cancel)
	raw, e := s.raw.open(setup, authority, c.headers(authority))
	stop()
	cancel()
	if e != nil {
		<-c.capacity
		if IsCode(e, Auth) || !s.raw.alive() {
			c.invalidate(s, e)
		}
		return nil, e
	}
	v := &clientStream{Conn: raw, c: c, s: s}
	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		_ = raw.Close()
		<-c.capacity
		return nil, failure(Unavailable, nil)
	}
	s.streams[v] = true
	s.mu.Unlock()
	s.lastUse.Store(time.Now().UnixNano())
	s.received()
	return v, nil
}
func (c *Client) Open(ctx context.Context, authority string) (net.Conn, error) {
	a, e := wire.Authority(authority)
	if e != nil {
		return nil, failure(Config, e)
	}
	s, e := c.acquire(ctx)
	if e != nil {
		return nil, e
	}
	return c.openSession(ctx, s, a)
}

type clientStream struct {
	net.Conn
	c    *Client
	s    *clientSession
	once sync.Once
}

func (s *clientStream) Read(p []byte) (int, error) {
	n, e := s.Conn.Read(p)
	if n > 0 {
		s.s.received()
		s.s.lastUse.Store(time.Now().UnixNano())
	}
	return n, e
}
func (s *clientStream) Write(p []byte) (int, error) {
	n, e := s.Conn.Write(p)
	if n > 0 {
		s.s.lastUse.Store(time.Now().UnixNano())
	}
	return n, e
}
func (s *clientStream) CloseWrite() error {
	if h, ok := s.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return s.Close()
}
func (s *clientStream) Close() error {
	s.once.Do(func() {
		_ = s.Conn.Close()
		s.s.mu.Lock()
		delete(s.s.streams, s)
		s.s.mu.Unlock()
		<-s.c.capacity
		s.s.lastUse.Store(time.Now().UnixNano())
	})
	return nil
}
func (c *Client) Check(ctx context.Context) error {
	s, e := c.acquire(ctx)
	if e != nil {
		return e
	}
	return c.checkSession(ctx, s)
}
func (c *Client) checkSession(ctx context.Context, s *clientSession) error {
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		return failure(Closed, net.ErrClosed)
	}
	s.mu.Lock()
	f := s.check
	if f == nil {
		check, cancel := context.WithTimeout(s.ctx, c.config.HealthTimeout)
		f = &healthFlight{done: make(chan struct{}), cancel: cancel}
		s.check = f
		c.workers.Add(1)
		go func() {
			defer c.workers.Done()
			raw, e := s.raw.open(check, "_check", c.headers("_check"))
			if raw != nil {
				finishCheck(raw)
			}
			cancel()
			s.mu.Lock()
			data := f.data
			s.check = nil
			if data && !IsCode(e, Auth) {
				e = nil
			}
			if e != nil && !IsCode(e, Auth) {
				e = failure(HealthTimeout, e)
			}
			f.err = e
			if e != nil {
				s.cancel()
			}
			s.mu.Unlock()
			if e != nil {
				c.invalidate(s, e)
			} else {
				s.lastRx.Store(time.Now().UnixNano())
			}
			close(f.done)
		}()
	}
	s.mu.Unlock()
	c.mu.Unlock()
	select {
	case <-f.done:
		return f.err
	case <-ctx.Done():
		return failure(HealthTimeout, ctx.Err())
	case <-s.ctx.Done():
		<-f.done
		if f.err != nil {
			return f.err
		}
		return failure(Unavailable, nil)
	}
}

func finishCheck(stream net.Conn) {
	if h, ok := stream.(interface{ CloseWrite() error }); ok {
		_ = h.CloseWrite()
	}
	_ = stream.Close()
}
func (c *Client) Close() error {
	c.mu.Lock()
	if c.state == Closing || c.state == ClosedState {
		joined := c.joined
		c.mu.Unlock()
		<-joined
		return nil
	}
	c.state = Closing
	c.cancel()
	s := c.session
	c.session = nil
	c.mu.Unlock()
	if s != nil {
		s.close()
	}
	c.workers.Wait()
	c.mu.Lock()
	c.state = ClosedState
	close(c.joined)
	c.mu.Unlock()
	return nil
}
