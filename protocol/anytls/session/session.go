package session

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/protocol/anytls/padding"
	"github.com/ike-sh/Splicore/protocol/anytls/wire"
)

var ErrLimit = errors.New("AnyTLS resource limit reached")
var ErrOpen = errors.New("AnyTLS destination unavailable")
var ErrAlert = errors.New("AnyTLS peer closed session with an alert")

// mu protects all stream metadata and owned queues. No socket I/O is performed
// while holding it. output serializes complete protocol writes, not readers.
type Session struct {
	mu              sync.Mutex
	conn            net.Conn
	cfg             Config
	client          bool
	version         int
	settingsDone    bool
	lastID          uint32
	streams         map[uint32]*Stream
	buffered        int
	changed         chan struct{}
	done            chan struct{}
	readerDone      chan struct{}
	output          chan struct{}
	writer          *padding.Writer
	pendingSettings []byte
	handler         func(*Stream)
	closed          bool
	err             error
	ctx             context.Context
	cancel          context.CancelFunc
	workers         sync.WaitGroup
	lastActivity    time.Time
	idleSince       time.Time
	heartSent       time.Time
	writeMu         sync.Mutex
	activeWrite     *Stream
	activeBase      time.Time
	writing         bool
}

func NewClient(conn net.Conn, key wire.AuthKey, config Config) (*Session, error) {
	cfg, err := config.defaults()
	if err != nil {
		conn.Close()
		return nil, err
	}
	n, err := cfg.Padding.AuthLength(cfg.Random)
	if err != nil || n < 0 || n > wire.MaxPayload {
		conn.Close()
		return nil, wire.ErrProtocol
	}
	auth, _ := wire.Authentication(key, make([]byte, n))
	_ = conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
	err = wire.WriteAll(conn, auth)
	clear(auth)
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetWriteDeadline(time.Time{})
	s := newSession(conn, cfg, true, nil)
	s.pendingSettings = []byte("v=" + strconv.Itoa(cfg.Version) + "\nclient=" + cfg.ClientMetadata + "\npadding-md5=" + cfg.Padding.Hash())
	s.start()
	return s, nil
}

// Authentication is validated by the server adapter before constructing this
// session, so rejected identities cannot reach the command dispatcher.
func NewServer(conn net.Conn, config Config, handler func(*Stream)) (*Session, error) {
	cfg, err := config.defaults()
	if err != nil || handler == nil {
		conn.Close()
		return nil, wire.ErrProtocol
	}
	s := newSession(conn, cfg, false, handler)
	s.start()
	return s, nil
}

func newSession(conn net.Conn, cfg Config, client bool, handler func(*Stream)) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{conn: conn, cfg: cfg, client: client, version: 1, streams: map[uint32]*Stream{}, changed: make(chan struct{}), done: make(chan struct{}), readerDone: make(chan struct{}), output: make(chan struct{}, 1), writer: padding.NewWriter(conn, cfg.Padding, cfg.Random), handler: handler, ctx: ctx, cancel: cancel, lastActivity: time.Now()}
	s.output <- struct{}{}
	s.idleSince = time.Now()
	return s
}
func (s *Session) start() {
	if s.cfg.Version == 2 && s.client {
		s.workers.Add(1)
		go s.watchHeartbeat()
	}
	go s.read()
}
func (s *Session) signal()                  { close(s.changed); s.changed = make(chan struct{}) }
func (s *Session) Context() context.Context { return s.ctx }
func (s *Session) Done() <-chan struct{}    { return s.done }
func (s *Session) Version() int             { s.mu.Lock(); defer s.mu.Unlock(); return s.version }
func (s *Session) Active() int              { s.mu.Lock(); defer s.mu.Unlock(); return len(s.streams) }
func (s *Session) IdleSince() time.Time     { s.mu.Lock(); defer s.mu.Unlock(); return s.idleSince }
func (s *Session) Err() error               { s.mu.Lock(); defer s.mu.Unlock(); return s.err }
func (s *Session) Wait()                    { <-s.readerDone; s.workers.Wait() }
func (s *Session) Close() error             { s.shutdown(net.ErrClosed); return nil }

func (s *Session) shutdown(err error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed, s.err = true, err
	close(s.done)
	s.cancel()
	for _, st := range s.streams {
		st.terminateLocked(err, false)
	}
	clear(s.streams)
	s.signal()
	s.mu.Unlock()
	_ = s.conn.Close()
}

func (s *Session) acquire(ctx context.Context, st *Stream) error {
	for {
		deadline := time.Now().Add(s.cfg.WriteTimeout)
		var changed <-chan struct{}
		if st != nil {
			s.mu.Lock()
			if st.closed {
				s.mu.Unlock()
				return net.ErrClosed
			}
			deadline = sooner(deadline, st.writeDeadline)
			changed = st.changed
			s.mu.Unlock()
		}
		if d, ok := ctx.Deadline(); ok {
			deadline = sooner(deadline, d)
		}
		timer := time.NewTimer(time.Until(deadline))
		select {
		case <-s.output:
			timer.Stop()
			return nil
		case <-s.done:
			timer.Stop()
			return net.ErrClosed
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
			return os.ErrDeadlineExceeded
		case <-changed:
			timer.Stop()
		}
	}
}
func (s *Session) release() { s.output <- struct{}{} }

func (s *Session) writeHeld(ctx context.Context, st *Stream, b []byte) error {
	base := time.Now().Add(s.cfg.WriteTimeout)
	if d, ok := ctx.Deadline(); ok {
		base = sooner(base, d)
	}
	s.writeMu.Lock()
	deadline := base
	s.mu.Lock()
	if s.closed || st != nil && st.closed {
		s.mu.Unlock()
		s.writeMu.Unlock()
		return net.ErrClosed
	}
	if st != nil {
		deadline = sooner(deadline, st.writeDeadline)
	}
	s.mu.Unlock()
	if ctx.Err() != nil {
		s.writeMu.Unlock()
		return ctx.Err()
	}
	if !deadline.After(time.Now()) {
		s.writeMu.Unlock()
		return os.ErrDeadlineExceeded
	}
	s.activeWrite, s.activeBase, s.writing = st, base, true
	_ = s.conn.SetWriteDeadline(deadline)
	s.writeMu.Unlock()
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		s.writeMu.Lock()
		if s.writing {
			_ = s.conn.SetWriteDeadline(time.Now())
		}
		s.writeMu.Unlock()
		close(interrupted)
	})
	err := s.writer.Write(b)
	if !stop() {
		<-interrupted
	}
	s.writeMu.Lock()
	s.activeWrite, s.writing = nil, false
	_ = s.conn.SetWriteDeadline(time.Time{})
	s.writeMu.Unlock()
	if err != nil {
		s.shutdown(err)
		return err
	}
	s.mu.Lock()
	s.lastActivity = time.Now()
	s.mu.Unlock()
	return nil
}

// A deadline belongs to the stream currently writing. Other streams must not
// change a shared socket deadline. A partial failed protocol write is fatal.
func (s *Session) refreshWriteDeadline(st *Stream) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if !s.writing || s.activeWrite != st {
		return
	}
	s.mu.Lock()
	deadline := sooner(s.activeBase, st.writeDeadline)
	if st.closed {
		deadline = time.Now()
	}
	s.mu.Unlock()
	_ = s.conn.SetWriteDeadline(deadline)
}

func (s *Session) send(st *Stream, frames ...wire.Frame) error {
	if err := s.acquire(s.ctx, st); err != nil {
		return err
	}
	defer s.release()
	var b []byte
	for _, f := range frames {
		var err error
		b, err = wire.AppendFrame(b, f)
		if err != nil {
			return err
		}
	}
	return s.writeHeld(s.ctx, st, b)
}

func (s *Session) streamLocked(id uint32) *Stream {
	ctx, cancel := context.WithCancel(s.ctx)
	st := &Stream{session: s, id: id, changed: make(chan struct{}), writeOrder: make(chan struct{}, 1), ctx: ctx, cancel: cancel}
	st.writeOrder <- struct{}{}
	s.streams[id] = st
	s.idleSince = time.Time{}
	return st
}

func (s *Session) removeLocked(id uint32) {
	delete(s.streams, id)
	if len(s.streams) == 0 && s.idleSince.IsZero() {
		s.idleSince = time.Now()
	}
}

// Open groups Settings, SYN and the initial destination bytes into the first
// session plaintext write. ID allocation happens under output admission, keeping
// the wire's SYN order monotonic even when callers open concurrently.
func (s *Session) Open(ctx context.Context, initial []byte) (*Stream, error) {
	if !s.client || len(initial) == 0 || len(initial) > 512 {
		return nil, wire.ErrProtocol
	}
	if err := s.acquire(ctx, nil); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.closed || len(s.streams) >= s.cfg.MaxStreams || s.lastID == math.MaxUint32 {
		s.mu.Unlock()
		s.release()
		return nil, ErrLimit
	}
	s.lastID++
	st := s.streamLocked(s.lastID)
	s.mu.Unlock()
	var b []byte
	if s.pendingSettings != nil {
		b, _ = wire.AppendFrame(b, wire.Frame{Command: wire.Settings, Payload: s.pendingSettings})
		s.pendingSettings = nil
	}
	b, _ = wire.AppendFrame(b, wire.Frame{Command: wire.Open, Stream: st.id})
	b, _ = wire.AppendFrame(b, wire.Frame{Command: wire.Data, Stream: st.id, Payload: initial})
	err := s.writeHeld(ctx, st, b)
	s.release()
	if err == nil {
		err = st.waitOpen(ctx)
	}
	if err != nil {
		st.Close()
		return nil, err
	}
	return st, nil
}

func (s *Session) read() {
	defer close(s.readerDone)
	defer s.shutdown(net.ErrClosed)
	for {
		frame, err := wire.ReadFrame(s.conn)
		if err != nil {
			s.shutdown(err)
			return
		}
		s.mu.Lock()
		s.lastActivity = time.Now()
		s.mu.Unlock()
		if err = s.dispatch(frame); err != nil {
			if !s.client {
				_ = s.send(nil, wire.Frame{Command: wire.Alert, Payload: []byte("invalid session input")})
			}
			s.shutdown(err)
			return
		}
	}
}

func (s *Session) dispatch(f wire.Frame) error {
	switch f.Command {
	case wire.Waste:
		return nil
	case wire.Settings:
		if s.client || f.Stream != 0 {
			return wire.ErrProtocol
		}
		values, err := wire.ParseSettings(f.Payload)
		if err != nil {
			return err
		}
		s.mu.Lock()
		if s.settingsDone || s.closed {
			s.mu.Unlock()
			return wire.ErrProtocol
		}
		s.settingsDone = true
		_ = s.conn.SetReadDeadline(time.Time{})
		if s.cfg.Version == 2 && wire.Version(values) == 2 {
			s.version = 2
		}
		v := s.version
		s.signal()
		s.mu.Unlock()
		var frames []wire.Frame
		if v == 2 {
			frames = append(frames, wire.Frame{Command: wire.ServerSettings, Payload: []byte("v=2")})
		}
		if values["padding-md5"] != s.cfg.Padding.Hash() {
			frames = append(frames, wire.Frame{Command: wire.PaddingUpdate, Payload: []byte(s.cfg.Padding.Text())})
		}
		if len(frames) > 0 {
			return s.send(nil, frames...)
		}
		return nil
	case wire.ServerSettings:
		if !s.client || s.cfg.Version != 2 || f.Stream != 0 {
			return wire.ErrProtocol
		}
		values, err := wire.ParseSettings(f.Payload)
		if err != nil {
			return err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.settingsDone {
			return wire.ErrProtocol
		}
		s.settingsDone = true
		s.version = wire.Version(values)
		s.signal()
		return nil
	case wire.PaddingUpdate:
		if !s.client || f.Stream != 0 {
			return wire.ErrProtocol
		}
		scheme, err := padding.Parse(string(f.Payload))
		if err != nil {
			return err
		}
		if s.cfg.OnPadding != nil {
			s.cfg.OnPadding(scheme)
		}
		return nil
	case wire.Open:
		if s.client || f.Stream == 0 {
			return wire.ErrProtocol
		}
		s.mu.Lock()
		if !s.settingsDone || s.closed || f.Stream <= s.lastID {
			s.mu.Unlock()
			return wire.ErrProtocol
		}
		s.lastID = f.Stream
		if len(s.streams) >= s.cfg.MaxStreams {
			s.mu.Unlock()
			return ErrLimit
		}
		st := s.streamLocked(f.Stream)
		s.workers.Add(1)
		s.mu.Unlock()
		go func() { defer s.workers.Done(); defer st.Close(); s.handler(st) }()
		return nil
	case wire.Data:
		if f.Stream == 0 {
			return wire.ErrProtocol
		}
		s.mu.Lock()
		st := s.streams[f.Stream]
		if st == nil {
			unknown := f.Stream > s.lastID
			s.mu.Unlock()
			if unknown {
				return wire.ErrProtocol
			}
			return nil
		}
		if len(f.Payload)+st.buffered > s.cfg.MaxStreamBuffer || len(f.Payload)+s.buffered > s.cfg.MaxSessionBuffer {
			st.terminateLocked(ErrLimit, false)
			s.removeLocked(f.Stream)
			s.signal()
			s.mu.Unlock()
			return s.send(nil, wire.Frame{Command: wire.Finish, Stream: f.Stream})
		}
		if len(f.Payload) > 0 {
			st.queue = append(st.queue, f.Payload)
			st.buffered += len(f.Payload)
			s.buffered += len(f.Payload)
			st.signalLocked()
		}
		s.mu.Unlock()
		return nil
	case wire.Finish:
		if f.Stream == 0 {
			return wire.ErrProtocol
		}
		s.mu.Lock()
		if st := s.streams[f.Stream]; st != nil {
			st.terminateLocked(io.EOF, true)
			s.removeLocked(f.Stream)
			s.signal()
		}
		s.mu.Unlock()
		return nil
	case wire.OpenResult:
		if !s.client || f.Stream == 0 {
			return wire.ErrProtocol
		}
		s.mu.Lock()
		if s.version != 2 {
			s.mu.Unlock()
			return wire.ErrProtocol
		}
		if st := s.streams[f.Stream]; st != nil {
			if st.ackDone {
				s.mu.Unlock()
				return wire.ErrProtocol
			}
			st.ackDone = true
			if len(f.Payload) > 0 {
				st.ackErr = ErrOpen
				st.terminateLocked(ErrOpen, false)
				s.removeLocked(f.Stream)
				s.signal()
			}
			st.signalLocked()
		}
		s.mu.Unlock()
		return nil
	case wire.Heartbeat, wire.HeartbeatReply:
		if f.Stream != 0 || s.Version() != 2 {
			return wire.ErrProtocol
		}
		if f.Command == wire.Heartbeat {
			return s.send(nil, wire.Frame{Command: wire.HeartbeatReply})
		}
		s.mu.Lock()
		s.heartSent = time.Time{}
		s.mu.Unlock()
		return nil
	case wire.Alert:
		if !s.client || f.Stream != 0 {
			return wire.ErrProtocol
		}
		if s.cfg.OnAlert != nil {
			s.cfg.OnAlert(len(f.Payload))
		}
		return ErrAlert
	}
	return wire.ErrProtocol
}

func (s *Session) watchHeartbeat() {
	defer s.workers.Done()
	period := s.cfg.HeartbeatInterval
	if s.cfg.HeartbeatTimeout < period {
		period = s.cfg.HeartbeatTimeout
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case now := <-ticker.C:
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				return
			}
			if s.version != 2 {
				s.mu.Unlock()
				continue
			}
			if !s.heartSent.IsZero() {
				expired := now.Sub(s.heartSent) >= s.cfg.HeartbeatTimeout
				s.mu.Unlock()
				if expired {
					s.shutdown(os.ErrDeadlineExceeded)
					return
				}
				continue
			}
			if now.Sub(s.lastActivity) < s.cfg.HeartbeatInterval {
				s.mu.Unlock()
				continue
			}
			s.heartSent = now
			s.mu.Unlock()
			if err := s.send(nil, wire.Frame{Command: wire.Heartbeat}); err != nil {
				s.shutdown(err)
				return
			}
		}
	}
}
