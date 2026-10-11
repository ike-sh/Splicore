package session

import (
	"context"
	"math"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/protocol/anytls/padding"
	"github.com/ike-sh/Splicore/protocol/anytls/wire"
)

type PoolConfig struct {
	Session          Config
	IdleCheck        time.Duration
	IdleTimeout      time.Duration
	MinIdle          int
	MaxSessions      int
	MultiplexStreams int
}

func (c PoolConfig) defaults() (PoolConfig, error) {
	var err error
	c.Session, err = c.Session.defaults()
	if err != nil {
		return c, err
	}
	if c.IdleCheck == 0 {
		c.IdleCheck = 30 * time.Second
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 30 * time.Second
	}
	if c.MaxSessions == 0 {
		c.MaxSessions = 128
	}
	if c.MultiplexStreams == 0 {
		c.MultiplexStreams = 1
	}
	if c.IdleCheck < time.Millisecond || c.IdleCheck > time.Hour || c.IdleTimeout < time.Millisecond || c.IdleTimeout > 24*time.Hour || c.MinIdle < 0 || c.MinIdle > c.MaxSessions || c.MaxSessions < 1 || c.MaxSessions > 128 || c.MultiplexStreams < 1 || c.MultiplexStreams > c.Session.MaxStreams {
		return c, wire.ErrProtocol
	}
	return c, nil
}

type poolEntry struct {
	session  *Session
	sequence uint64
	reserved int
}

type Client struct {
	mu          sync.Mutex
	cfg         PoolConfig
	dial        Dial
	key         wire.AuthKey
	scheme      *padding.Scheme
	entries     map[*Session]*poolEntry
	sequence    uint64
	pending     int
	closed      bool
	ctx         context.Context
	cancel      context.CancelFunc
	operations  sync.WaitGroup
	janitorDone chan struct{}
	closeDone   chan struct{}
	once        sync.Once
}

func NewClientPool(dial Dial, key wire.AuthKey, config PoolConfig) (*Client, error) {
	cfg, err := config.defaults()
	if err != nil || dial == nil {
		return nil, wire.ErrProtocol
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{cfg: cfg, dial: dial, key: key, scheme: cfg.Session.Padding, entries: map[*Session]*poolEntry{}, ctx: ctx, cancel: cancel, janitorDone: make(chan struct{}), closeDone: make(chan struct{})}
	go c.cleanIdle()
	return c, nil
}

func (c *Client) chooseLocked() *poolEntry {
	var idle, active *poolEntry
	for session, entry := range c.entries {
		select {
		case <-session.Done():
			// The janitor retains ownership until it has joined all workers.
			continue
		default:
		}
		n := session.Active() + entry.reserved
		if n == 0 && (idle == nil || entry.sequence > idle.sequence) {
			idle = entry
		}
		if c.cfg.MultiplexStreams > 1 && n < c.cfg.MultiplexStreams && (active == nil || entry.sequence > active.sequence) {
			active = entry
		}
	}
	if idle != nil {
		return idle
	}
	return active
}

func (c *Client) Open(ctx context.Context, initial []byte) (*Stream, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	c.operations.Add(1)
	entry := c.chooseLocked()
	if entry != nil {
		entry.reserved++
	}
	create := entry == nil
	if create && (len(c.entries)+c.pending >= c.cfg.MaxSessions || c.sequence == math.MaxUint64) {
		c.mu.Unlock()
		c.operations.Done()
		return nil, ErrLimit
	}
	var sequence uint64
	if create {
		c.pending++
		c.sequence++
		sequence = c.sequence
	}
	scheme, key := c.scheme, c.key
	c.mu.Unlock()
	defer c.operations.Done()
	joined, cancel := context.WithCancel(ctx)
	stopOwner := context.AfterFunc(c.ctx, cancel)
	defer func() { stopOwner(); cancel() }()
	if create {
		conn, err := c.dial(joined)
		var session *Session
		if err == nil {
			interrupted := make(chan struct{})
			stop := context.AfterFunc(joined, func() { conn.Close(); close(interrupted) })
			cfg := c.cfg.Session
			cfg.Padding = scheme
			previous := cfg.OnPadding
			cfg.OnPadding = func(next *padding.Scheme) {
				c.mu.Lock()
				if !c.closed {
					c.scheme = next
				}
				c.mu.Unlock()
				if previous != nil {
					previous(next)
				}
			}
			session, err = NewClient(conn, key, cfg)
			if !stop() {
				<-interrupted
			}
		}
		c.mu.Lock()
		c.pending--
		if err == nil && c.closed {
			err = net.ErrClosed
		}
		if err == nil {
			entry = &poolEntry{session: session, sequence: sequence, reserved: 1}
			c.entries[session] = entry
		}
		c.mu.Unlock()
		if err != nil {
			if session != nil {
				session.Close()
				session.Wait()
			}
			return nil, err
		}
	}
	stream, err := entry.session.Open(joined, initial)
	c.mu.Lock()
	entry.reserved--
	c.mu.Unlock()
	return stream, err
}

func (c *Client) cleanIdle() {
	defer close(c.janitorDone)
	ticker := time.NewTicker(c.cfg.IdleCheck)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case now := <-ticker.C:
			c.mu.Lock()
			var idle []*poolEntry
			var closeList []*Session
			for session, entry := range c.entries {
				select {
				case <-session.Done():
					delete(c.entries, session)
					closeList = append(closeList, session)
					continue
				default:
				}
				if entry.reserved == 0 && session.Active() == 0 {
					idle = append(idle, entry)
				}
			}
			sort.Slice(idle, func(i, j int) bool { return idle[i].sequence > idle[j].sequence })
			for i, entry := range idle {
				if i >= c.cfg.MinIdle && now.Sub(entry.session.IdleSince()) >= c.cfg.IdleTimeout {
					delete(c.entries, entry.session)
					closeList = append(closeList, entry.session)
				}
			}
			c.mu.Unlock()
			for _, session := range closeList {
				session.Close()
				session.Wait()
			}
		}
	}
}

type PoolState struct {
	Sessions, Pending, ActiveStreams int
	LastSequence                     uint64
	PaddingHash                      string
}

func (c *Client) State() PoolState {
	c.mu.Lock()
	defer c.mu.Unlock()
	state := PoolState{Sessions: len(c.entries), Pending: c.pending, LastSequence: c.sequence, PaddingHash: c.scheme.Hash()}
	for session := range c.entries {
		state.ActiveStreams += session.Active()
	}
	return state
}

func (c *Client) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.cancel()
		all := make([]*Session, 0, len(c.entries))
		for session := range c.entries {
			all = append(all, session)
		}
		clear(c.entries)
		clear(c.key[:])
		c.mu.Unlock()
		for _, session := range all {
			session.Close()
		}
		c.operations.Wait()
		<-c.janitorDone
		for _, session := range all {
			session.Wait()
		}
		close(c.closeDone)
	})
	<-c.closeDone
	return nil
}
