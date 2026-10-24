package encryption

import (
	"context"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"lukechampine.com/blake3"
)

var responseNonce = [12]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}

func (c *Config) relaySize() int {
	size := 32 * (len(c.keys) - 1)
	for _, k := range c.keys {
		if k.xPublic != nil {
			size += 32
		} else {
			size += 1088
		}
	}
	return size
}

func (c *Config) clientAuth() (iv, wire, secret []byte, err error) {
	iv = make([]byte, 16)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}
	wire = make([]byte, c.relaySize())
	offset := 0
	var previous cipher.Stream
	for j, k := range c.keys {
		var ephemeral []byte
		if k.xPublic != nil {
			var private *ecdh.PrivateKey
			private, err = ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return
			}
			secret, err = private.ECDH(k.xPublic)
			if err != nil {
				return
			}
			ephemeral = private.PublicKey().Bytes()
		} else {
			secret, ephemeral = k.kemPublic.Encapsulate()
		}
		out := wire[offset : offset+len(ephemeral)]
		copy(out, ephemeral)
		if c.mode != "native" {
			stream(k.public, iv).XORKeyStream(out, out)
		}
		if previous != nil {
			previous.XORKeyStream(out[:32], out[:32])
		}
		offset += len(ephemeral)
		if j+1 < len(c.keys) {
			nextHash := blake3.Sum256(c.keys[j+1].public)
			previous = stream(secret, iv)
			previous.XORKeyStream(wire[offset:offset+32], nextHash[:])
			offset += 32
		}
	}
	return
}

func (c *Config) serverAuth(conn net.Conn) (iv, secret []byte, err error) {
	wire := make([]byte, 16+c.relaySize())
	if _, err = io.ReadFull(conn, wire); err != nil {
		return
	}
	iv = wire[:16]
	offset := 16
	var previous cipher.Stream
	for j, k := range c.keys {
		size := 32
		if k.kemPrivate != nil {
			size = 1088
		}
		part := wire[offset : offset+size]
		if previous != nil {
			previous.XORKeyStream(part[:32], part[:32])
		}
		if c.mode != "native" {
			stream(k.public, iv).XORKeyStream(part, part)
		}
		if k.xPrivate != nil {
			if part[31]&128 != 0 {
				return nil, nil, ErrHandshake
			}
			var peer *ecdh.PublicKey
			peer, err = ecdh.X25519().NewPublicKey(part)
			if err != nil {
				return
			}
			secret, err = k.xPrivate.ECDH(peer)
		} else {
			secret, err = k.kemPrivate.Decapsulate(part)
		}
		if err != nil {
			return
		}
		offset += size
		if j+1 < len(c.keys) {
			previous = stream(secret, iv)
			part = wire[offset : offset+32]
			previous.XORKeyStream(part, part)
			expected := blake3.Sum256(c.keys[j+1].public)
			if subtle.ConstantTimeCompare(part, expected[:]) != 1 {
				return nil, nil, ErrHandshake
			}
			offset += 32
		}
	}
	return
}

func paddingPlan(c *Config) (sizes []int, gaps []time.Duration, total int, err error) {
	tuples := c.paddingTuples()
	for n, t := range tuples {
		var probability, value int
		probability, err = randomBetween(0, 100)
		if err != nil {
			return
		}
		if t.probability >= probability {
			value, err = randomBetween(t.low, t.high)
			if err != nil {
				return
			}
		}
		if n%2 == 0 {
			sizes = append(sizes, value)
			total += value
		} else {
			gaps = append(gaps, time.Duration(value)*time.Millisecond)
		}
	}
	return
}

func paddingEnvelope(a *cryptor, total int) []byte {
	out := a.seal(number(total-18), nil)
	return append(out, a.seal(make([]byte, total-34), nil)...)
}

func sendHello(ctx context.Context, conn net.Conn, prefix, padding []byte, sizes []int, gaps []time.Duration) error {
	hello := append(prefix, padding...)
	sizes[0] += len(prefix)
	for n, size := range sizes {
		if size > 0 {
			if e := writeAll(conn, hello[:size]); e != nil {
				return e
			}
			hello = hello[size:]
		}
		if n < len(gaps) && gaps[n] > 0 {
			timer := time.NewTimer(gaps[n])
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			}
		}
	}
	return nil
}

func readOpen(conn net.Conn, a *cryptor, size int) ([]byte, error) {
	if size < 16 || size > 65535 {
		return nil, ErrHandshake
	}
	b := make([]byte, size)
	if _, e := io.ReadFull(conn, b); e != nil {
		return nil, e
	}
	p, e := a.open(b, nil)
	if e != nil {
		return nil, ErrHandshake
	}
	return p, nil
}

func readLength(conn net.Conn, a *cryptor) (int, error) {
	b, e := readOpen(conn, a, 18)
	if e != nil {
		return 0, e
	}
	return int(binary.BigEndian.Uint16(b)), nil
}

func handshakeContext(ctx context.Context, conn net.Conn, cfg *Config) (context.Context, func()) {
	ctx, cancel := context.WithTimeout(ctx, cfg.handshakeTimeout())
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	return ctx, func() { stop(); cancel() }
}

// Client owns one ticket for one outbound node/account instance. Do not share
// it across identities. A failed old connection cannot invalidate newer state.
type Client struct {
	config     *Config
	mu         sync.Mutex
	ticket     [16]byte
	pfs        []byte
	expiry     time.Time
	generation uint64
	now        func() time.Time
	chooseAES  func() bool
}

func NewClient(c *Config) (*Client, error) {
	if c == nil || c.server {
		return nil, ErrConfig
	}
	return &Client{config: c, now: time.Now, chooseAES: preferAES}, nil
}

func (c *Client) invalidate(generation uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if generation == c.generation {
		c.expiry = time.Time{}
	}
}

func (c *Client) Handshake(ctx context.Context, raw net.Conn) (*Conn, error) {
	ctx, finish := handshakeContext(ctx, raw, c.config)
	defer finish()
	cfg := c.config
	iv, relays, nfs, e := cfg.clientAuth()
	if e != nil {
		return nil, ErrHandshake
	}
	aesMode := c.chooseAES()
	auth := newCryptor(iv, nfs, aesMode)
	conn := &Conn{Conn: raw, aesMode: aesMode}
	prefix := append(append([]byte(nil), iv...), relays...)
	c.mu.Lock()
	if cfg.resume && c.now().Before(c.expiry) {
		conn.united = append(append([]byte(nil), c.pfs...), nfs...)
		ticket := c.ticket
		conn.generation = c.generation
		c.mu.Unlock()
		prefix = append(prefix, auth.seal(number(32), nil)...)
		encryptedTicket := auth.seal(ticket[:], nil)
		prefix = append(prefix, encryptedTicket...)
		conn.prefix = prefix
		conn.tx = newCryptor(encryptedTicket, conn.united, aesMode)
		conn.client = c
		conn.resumed = true
		conn.random = cfg.mode == "random"
		if conn.random {
			conn.txMask = stream(conn.united, iv)
		}
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		return conn, nil
	}
	c.mu.Unlock()
	kem, e := mlkem.GenerateKey768()
	if e != nil {
		return nil, ErrHandshake
	}
	x, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return nil, ErrHandshake
	}
	clientPublic := append(kem.EncapsulationKey().Bytes(), x.PublicKey().Bytes()...)
	prefix = append(prefix, auth.seal(number(len(clientPublic)+16), nil)...)
	prefix = append(prefix, auth.seal(clientPublic, nil)...)
	sizes, gaps, total, e := paddingPlan(cfg)
	if e != nil {
		return nil, ErrHandshake
	}
	if e = sendHello(ctx, raw, prefix, paddingEnvelope(auth, total), sizes, gaps); e != nil {
		return nil, e
	}
	encrypted := make([]byte, 1136)
	if _, e = io.ReadFull(raw, encrypted); e != nil {
		return nil, e
	}
	serverPublic, e := auth.aead.Open(nil, responseNonce[:], encrypted, nil)
	if e != nil {
		return nil, ErrHandshake
	}
	kemSecret, e := kem.Decapsulate(serverPublic[:1088])
	if e != nil {
		return nil, ErrHandshake
	}
	peer, e := ecdh.X25519().NewPublicKey(serverPublic[1088:])
	if e != nil {
		return nil, ErrHandshake
	}
	xSecret, e := x.ECDH(peer)
	if e != nil {
		return nil, ErrHandshake
	}
	pfs := append(kemSecret, xSecret...)
	conn.united = append(append([]byte(nil), pfs...), nfs...)
	conn.tx = newCryptor(clientPublic, conn.united, aesMode)
	conn.rx = newCryptor(serverPublic, conn.united, aesMode)
	ticket, e := readOpen(raw, conn.rx, 32)
	if e != nil {
		return nil, e
	}
	length, e := readLength(raw, conn.rx)
	if e != nil || length < 16 {
		return nil, ErrHandshake
	}
	conn.peerPadding = length
	if cfg.mode == "random" {
		conn.txMask = stream(conn.united, iv)
		conn.rxMask = stream(conn.united, ticket)
	}
	if cfg.resume {
		seconds := binary.BigEndian.Uint16(ticket)
		if seconds > 0 {
			c.mu.Lock()
			c.ticket = [16]byte(ticket)
			c.pfs = append([]byte(nil), pfs...)
			c.expiry = c.now().Add(time.Duration(seconds) * time.Second)
			c.generation++
			c.mu.Unlock()
		}
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	return conn, nil
}

type session struct {
	pfs     []byte
	expires time.Time
	used    map[[32]byte]struct{}
}

// Server state belongs to one inbound. Eviction invalidates a whole session;
// removing replay entries while retaining its ticket would permit replay.
type Server struct {
	config   *Config
	mu       sync.Mutex
	sessions map[[16]byte]*session
	closed   bool
	now      func() time.Time
}

const (
	maxSessions = 1024
	maxResumes  = 4096
)

func NewServer(c *Config) (*Server, error) {
	if c == nil || !c.server {
		return nil, ErrConfig
	}
	return &Server{config: c, sessions: make(map[[16]byte]*session), now: time.Now}, nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	clear(s.sessions)
	return nil
}
func (s *Server) active() bool { s.mu.Lock(); defer s.mu.Unlock(); return !s.closed }
func (s *Server) resume(ticket []byte, nfs []byte) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := [16]byte(ticket)
	state := s.sessions[id]
	if s.closed || state == nil {
		return nil, false
	}
	if !s.now().Before(state.expires) || len(state.used) >= maxResumes {
		delete(s.sessions, id)
		return nil, false
	}
	key := [32]byte(nfs)
	if _, seen := state.used[key]; seen {
		return nil, false
	}
	state.used[key] = struct{}{}
	return append([]byte(nil), state.pfs...), true
}

func (s *Server) issue(pfs []byte) ([]byte, error) {
	cfg := s.config
	var seconds int
	var e error
	if cfg.to == 0 {
		var percentage int
		percentage, e = randomBetween(50, 100)
		seconds = cfg.from * percentage / 100
	} else {
		seconds, e = randomBetween(cfg.from, cfg.to)
	}
	if e != nil {
		return nil, e
	}
	ticket := make([]byte, 16)
	if _, e = io.ReadFull(rand.Reader, ticket); e != nil {
		return nil, e
	}
	copy(ticket, number(seconds))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrHandshake
	}
	if seconds == 0 {
		return ticket, nil
	}
	now := s.now()
	for id, state := range s.sessions {
		if !now.Before(state.expires) {
			delete(s.sessions, id)
		}
	}
	if len(s.sessions) >= maxSessions {
		var oldest [16]byte
		var oldestTime time.Time
		for id, state := range s.sessions {
			if oldestTime.IsZero() || state.expires.Before(oldestTime) {
				oldest = id
				oldestTime = state.expires
			}
		}
		delete(s.sessions, oldest)
	}
	if _, collision := s.sessions[[16]byte(ticket)]; collision {
		return nil, ErrHandshake
	}
	expires := time.Unix(((now.Unix()+int64(max(cfg.from, cfg.to)))/60+2)*60, 0)
	s.sessions[[16]byte(ticket)] = &session{pfs: append([]byte(nil), pfs...), expires: expires, used: make(map[[32]byte]struct{})}
	return ticket, nil
}

func (s *Server) Handshake(ctx context.Context, raw net.Conn) (*Conn, error) {
	ctx, finish := handshakeContext(ctx, raw, s.config)
	defer finish()
	if !s.active() {
		return nil, ErrHandshake
	}
	cfg := s.config
	iv, nfs, e := cfg.serverAuth(raw)
	if e != nil {
		return nil, ErrHandshake
	}
	lengthWire := make([]byte, 18)
	if _, e = io.ReadFull(raw, lengthWire); e != nil {
		return nil, e
	}
	auth := newCryptor(iv, nfs, true)
	plain, e := auth.open(lengthWire, nil)
	aesMode := true
	if e != nil {
		aesMode = false
		auth = newCryptor(iv, nfs, false)
		plain, e = auth.open(lengthWire, nil)
	}
	if e != nil {
		return nil, ErrHandshake
	}
	size := int(binary.BigEndian.Uint16(plain))
	conn := &Conn{Conn: raw, aesMode: aesMode}
	if size == 32 {
		if cfg.from == 0 && cfg.to == 0 {
			return nil, ErrHandshake
		}
		encrypted := make([]byte, 32)
		if _, e = io.ReadFull(raw, encrypted); e != nil {
			return nil, e
		}
		ticket, e := auth.open(encrypted, nil)
		if e != nil {
			return nil, ErrHandshake
		}
		pfs, ok := s.resume(ticket, nfs)
		if !ok {
			noise := make([]byte, 1279)
			if _, e = io.ReadFull(rand.Reader, noise); e == nil {
				clear(noise[16:21])
				_ = writeAll(raw, noise)
			}
			return nil, ErrResume
		}
		conn.united = append(pfs, nfs...)
		conn.prefix = make([]byte, 16)
		if _, e = io.ReadFull(rand.Reader, conn.prefix); e != nil {
			return nil, ErrHandshake
		}
		conn.tx = newCryptor(conn.prefix, conn.united, aesMode)
		conn.rx = newCryptor(encrypted, conn.united, aesMode)
		conn.resumed = true
		if cfg.mode == "random" {
			conn.txMask = stream(conn.united, conn.prefix)
			conn.rxMask = stream(conn.united, iv)
		}
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		return conn, nil
	}
	if size < 1232 {
		return nil, ErrHandshake
	}
	clientPublic, e := readOpen(raw, auth, size)
	if e != nil {
		return nil, e
	}
	kem, e := mlkem.NewEncapsulationKey768(clientPublic[:1184])
	if e != nil {
		return nil, ErrHandshake
	}
	kemSecret, kemCipher := kem.Encapsulate()
	peer, e := ecdh.X25519().NewPublicKey(clientPublic[1184:1216])
	if e != nil {
		return nil, ErrHandshake
	}
	x, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return nil, ErrHandshake
	}
	xSecret, e := x.ECDH(peer)
	if e != nil {
		return nil, ErrHandshake
	}
	pfs := append(kemSecret, xSecret...)
	serverPublic := append(kemCipher, x.PublicKey().Bytes()...)
	conn.united = append(append([]byte(nil), pfs...), nfs...)
	conn.tx = newCryptor(serverPublic, conn.united, aesMode)
	conn.rx = newCryptor(clientPublic[:1216], conn.united, aesMode)
	ticket, e := s.issue(pfs)
	if e != nil {
		return nil, ErrHandshake
	}
	prefix := auth.aead.Seal(nil, responseNonce[:], serverPublic, nil)
	prefix = append(prefix, conn.tx.seal(ticket, nil)...)
	sizes, gaps, total, e := paddingPlan(cfg)
	if e != nil {
		return nil, ErrHandshake
	}
	if e = sendHello(ctx, raw, prefix, paddingEnvelope(conn.tx, total), sizes, gaps); e != nil {
		return nil, e
	}
	size, e = readLength(raw, auth)
	if e != nil {
		return nil, e
	}
	if _, e = readOpen(raw, auth, size); e != nil {
		return nil, e
	}
	if cfg.mode == "random" {
		conn.txMask = stream(conn.united, ticket)
		conn.rxMask = stream(conn.united, iv)
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	return conn, nil
}
