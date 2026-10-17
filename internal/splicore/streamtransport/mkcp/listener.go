package mkcp

import (
	"io"
	"net"
	"sync"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
)

const sessionLimit = 64
const listenerPayloadLimit = 128 << 20
const retiredTokenLimit = 4096
const retiredTokenTTL = 8 * time.Second

type peerKey struct {
	endpoint string
	token    uint16
}
type Listener struct {
	packet   net.PacketConn
	writer   *packetWriter
	config   cfg.MKCP
	mu       sync.Mutex
	sessions map[peerKey]*Conn
	held     map[*Conn]bool
	retired  map[peerKey]time.Time
	reserved uint64
	queue    chan *Conn
	done     chan struct{}
	readDone chan struct{}
	joined   chan struct{}
	closed   bool
	once     sync.Once
	owners   sync.WaitGroup
}

// NewListener takes ownership of the actual bound PacketConn on success.
// Reserving worst-case payload storage before admission bounds the listener,
// even when all peers stop acknowledging or all application readers stall.
func NewListener(packet net.PacketConn, m cfg.MKCP) (*Listener, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	l := &Listener{packet: packet, config: m, sessions: map[peerKey]*Conn{}, held: map[*Conn]bool{}, retired: map[peerKey]time.Time{},
		queue: make(chan *Conn, sessionLimit), done: make(chan struct{}), readDone: make(chan struct{}), joined: make(chan struct{})}
	l.writer = newPacketWriter()
	go l.receive()
	return l, nil
}
func (l *Listener) receive() {
	defer close(l.readDone)
	b := make([]byte, 65536)
	for {
		n, addr, err := l.packet.ReadFrom(b)
		if err != nil {
			go l.Close()
			return
		}
		rows, err := decode(b[:n], 1460)
		if err != nil {
			continue
		}
		key := peerKey{addr.String(), rows[0].token}
		now := time.Now()
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return
		}
		l.expireRetiredLocked(now)
		c := l.sessions[key]
		rejected := false
		if c == nil {
			if !l.canAdmitLocked(key) || rows[0].code != dataCode && rows[0].code != helloCode || rows[0].closing {
				l.mu.Unlock()
				continue
			}
			c = newConn(l.config, key.token, l.packet.LocalAddr(), addr, func(p []byte) error {
				if e := l.packet.SetWriteDeadline(time.Now().Add(socketWriteLimit)); e != nil {
					return e
				}
				n, e := l.packet.WriteTo(p, addr)
				if e == nil && n != len(p) {
					e = io.ErrShortWrite
				}
				return e
			}, func() {
				l.mu.Lock()
				delete(l.held, c)
				l.reserved -= l.config.PayloadBound()
				l.mu.Unlock()
			})
			c.onStopped = func() {
				l.mu.Lock()
				l.retireLocked(key, time.Now())
				l.mu.Unlock()
			}
			c.writer = l.writer
			l.sessions[key] = c
			l.held[c] = true
			l.reserved += l.config.PayloadBound()
			l.owners.Add(1)
			go func(c *Conn) { defer l.owners.Done(); c.run() }(c)
			select {
			case l.queue <- c:
			default:
				rejected = true
			}
		}
		l.mu.Unlock()
		if rejected {
			c.abort(net.ErrClosed)
		} else {
			c.input(rows)
		}
	}
}

// Each active demux session reserves its eventual retirement slot. Expiry only
// removes expired tombstones; no unexpired stale-token protection is evicted.
// All transitions hold l.mu and preserve len(retired)+len(sessions) <= 4096.
func (l *Listener) canAdmitLocked(key peerKey) bool {
	_, old := l.retired[key]
	return !old && l.sessions[key] == nil && len(l.held) < sessionLimit &&
		len(l.retired)+len(l.sessions) < retiredTokenLimit &&
		l.reserved+l.config.PayloadBound() <= listenerPayloadLimit
}
func (l *Listener) expireRetiredLocked(now time.Time) {
	for key, expiry := range l.retired {
		if !now.Before(expiry) {
			delete(l.retired, key)
		}
	}
}
func (l *Listener) retireLocked(key peerKey, now time.Time) {
	if l.sessions[key] == nil {
		return
	} // Duplicate notification preserves TTL.
	delete(l.sessions, key)
	l.retired[key] = now.Add(retiredTokenTTL)
}
func (l *Listener) Accept() (net.Conn, error) {
	for {
		select {
		case <-l.done:
			return nil, net.ErrClosed
		case c := <-l.queue:
			l.mu.Lock()
			closed := l.closed
			l.mu.Unlock()
			if closed {
				c.abort(net.ErrClosed)
				return nil, net.ErrClosed
			}
			c.mu.Lock()
			stopped := c.stopped
			c.mu.Unlock()
			if !stopped {
				return c, nil
			}
		}
	}
}
func (l *Listener) Addr() net.Addr      { return l.packet.LocalAddr() }
func (l *Listener) ActiveSessions() int { l.mu.Lock(); defer l.mu.Unlock(); return len(l.sessions) }
func (l *Listener) Close() error {
	l.once.Do(func() {
		l.mu.Lock()
		l.closed = true
		close(l.done)
		all := make([]*Conn, 0, len(l.held))
		for c := range l.held {
			all = append(all, c)
		}
		l.mu.Unlock()
		l.packet.Close()
		l.writer.close()
		for _, c := range all {
			c.abort(net.ErrClosed)
		}
		<-l.readDone
		l.owners.Wait()
		<-l.writer.joined
		for {
			select {
			case c := <-l.queue:
				c.abort(net.ErrClosed)
			default:
				close(l.joined)
				return
			}
		}
	})
	<-l.joined
	return nil
}
