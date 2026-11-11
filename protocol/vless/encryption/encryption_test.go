package encryption

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/mlkem"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func testConfigs(t *testing.T, auth, mode, policy string, count int) (*Config, *Config) {
	t.Helper()
	padding := os.Getenv("SPLICORE_PHASE32_TEST_PADDING")
	if padding == "" {
		padding = "100-35-35"
	}
	var sk, pk []string
	for range count {
		s, c, e := Generate(auth, mode, policy, "600s", padding)
		if e != nil {
			t.Fatal(e)
		}
		sk = append(sk, s[strings.LastIndex(s, ".")+1:])
		pk = append(pk, c[strings.LastIndex(c, ".")+1:])
	}
	s, e := ParseServer(method + "." + mode + ".600s." + padding + "." + strings.Join(sk, "."))
	if e != nil {
		t.Fatal(e)
	}
	c, e := ParseClient(method + "." + mode + "." + policy + "." + padding + "." + strings.Join(pk, "."))
	if e != nil {
		t.Fatal(e)
	}
	return s, c
}

func serveEcho(t *testing.T, s *Server) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	raws := map[net.Conn]bool{}
	closed := false
	wg.Go(func() {
		for {
			raw, e := l.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				raw.Close()
				return
			}
			raws[raw] = true
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				defer raw.Close()
				defer func() { mu.Lock(); delete(raws, raw); mu.Unlock() }()
				raw.SetDeadline(time.Now().Add(10 * time.Second))
				c, e := s.Handshake(context.Background(), raw)
				if e == nil {
					_, _ = io.Copy(c, c)
				}
			}()
		}
	})
	t.Cleanup(func() {
		mu.Lock()
		closed = true
		l.Close()
		for raw := range raws {
			raw.Close()
		}
		mu.Unlock()
		s.Close()
		wg.Wait()
	})
	return l.Addr().String()
}

func connect(t *testing.T, c *Client, address string) *Conn {
	t.Helper()
	raw, e := net.DialTimeout("tcp", address, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { raw.Close() })
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	conn, e := c.Handshake(context.Background(), raw)
	if e != nil {
		t.Fatal(e)
	}
	return conn
}

func exchange(t *testing.T, c net.Conn, size int) {
	t.Helper()
	p := make([]byte, size)
	for n := range p {
		p[n] = byte(n*37 + 11)
	}
	err := make(chan error, 1)
	go func() { err <- writeAll(c, p) }()
	got := make([]byte, size)
	_, e := io.ReadFull(c, got)
	if e != nil {
		t.Fatal(e)
	}
	if e = <-err; e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(p, got) {
		t.Fatal("payload mismatch")
	}
}

func TestEncryptedStreams(t *testing.T) {
	for _, mode := range []string{"native", "xorpub", "random"} {
		for _, auth := range []string{"x25519", "mlkem768"} {
			for _, aesMode := range []bool{true, false} {
				for _, policy := range []string{"1rtt", "0rtt"} {
					t.Run(fmt.Sprintf("%s/%s/aes=%v/%s", mode, auth, aesMode, policy), func(t *testing.T) {
						sc, cc := testConfigs(t, auth, mode, policy, 1)
						s, _ := NewServer(sc)
						c, _ := NewClient(cc)
						c.chooseAES = func() bool { return aesMode }
						address := serveEcho(t, s)
						for iteration := range 2 {
							conn := connect(t, c, address)
							if conn.resumed != (policy == "0rtt" && iteration > 0) {
								t.Fatal("wrong handshake path")
							}
							for _, size := range []int{0, 1, 31, 8191, 8192, 8193, 16624, 300000} {
								exchange(t, conn, size)
							}
							conn.Close()
						}
					})
				}
			}
		}
	}
}

func TestRelayChains(t *testing.T) {
	for _, auth := range []string{"x25519", "mlkem768"} {
		for _, mode := range []string{"native", "xorpub", "random"} {
			for _, count := range []int{2, 3} {
				t.Run(fmt.Sprintf("%s/%s/%d", auth, mode, count), func(t *testing.T) {
					sc, cc := testConfigs(t, auth, mode, "0rtt", count)
					s, _ := NewServer(sc)
					c, _ := NewClient(cc)
					address := serveEcho(t, s)
					exchange(t, connect(t, c, address), 32771)
					exchange(t, connect(t, c, address), 1)
				})
			}
		}
	}
}

func TestConfigAndKeyFormats(t *testing.T) {
	sc, cc := testConfigs(t, "x25519", "native", "0rtt", 1)
	if sc.ClientString(true) != cc.original {
		t.Fatal("public projection")
	}
	for _, server := range []bool{false, true} {
		for _, s := range []string{"", "NONE", "mlkem768x25519.native.0rtt.bad", "mlkem768x25519plus.unknown.0rtt.bad", method + ".native.0rtt.bad", strings.Repeat(".", 20000)} {
			if c, e := parse(s, server); e == nil {
				t.Fatalf("accepted invalid config (server=%v nil=%v)", server, c == nil)
			}
		}
		if c, e := parse("none", server); e != nil || c != nil {
			t.Fatal("none")
		}
	}
	for _, auth := range []string{"x25519", "mlkem768"} {
		s, c, e := Generate(auth, "native", "0rtt", "600s", "")
		if e != nil {
			t.Fatal(e)
		}
		private, _ := base64.RawURLEncoding.DecodeString(s[strings.LastIndex(s, ".")+1:])
		public, _ := base64.RawURLEncoding.DecodeString(c[strings.LastIndex(c, ".")+1:])
		if auth == "x25519" {
			k, e := ecdh.X25519().NewPrivateKey(private)
			if e != nil || !bytes.Equal(k.PublicKey().Bytes(), public) {
				t.Fatal("X25519 encoding")
			}
		} else {
			k, e := mlkem.NewDecapsulationKey768(private)
			if e != nil || !bytes.Equal(k.EncapsulationKey().Bytes(), public) {
				t.Fatal("ML-KEM encoding")
			}
			key, e := mlkem.NewEncapsulationKey768(public)
			if e != nil {
				t.Fatal(e)
			}
			secret, ct := key.Encapsulate()
			got, e := k.Decapsulate(ct)
			if e != nil || len(ct) != 1088 || !bytes.Equal(got, secret) {
				t.Fatal("ML-KEM roundtrip")
			}
		}
	}
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if _, e := ParseClient(method + ".native.0rtt." + key); e == nil {
		t.Fatal("low-order key")
	}
	for _, duration := range []string{"-1s", "65536s", "2-1s", "1h", "", "9999999999999999999999s"} {
		s := strings.Replace(sc.original, "600s", duration, 1)
		if _, e := ParseServer(s); e == nil {
			t.Fatal("invalid duration accepted")
		}
	}
	for _, padding := range []string{"99-35-35", "100-34-35", "100-35-65554", "100-35-35.100-0-1001", "100-35-35.100-2-1", "100-35-35-99", "100-35-35.0--1-2"} {
		s := strings.Replace(sc.original, "100-35-35", padding, 1)
		if _, e := ParseServer(s); e == nil {
			t.Fatal("invalid padding accepted")
		}
	}
}

func TestTicketConcurrencyExpiryRestart(t *testing.T) {
	sc, cc := testConfigs(t, "x25519", "random", "0rtt", 1)
	s, _ := NewServer(sc)
	c, _ := NewClient(cc)
	address := serveEcho(t, s)
	first := connect(t, c, address)
	exchange(t, first, 1)
	first.Close()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { conn := connect(t, c, address); exchange(t, conn, 16385); conn.Close() })
	}
	wg.Wait()
	c.mu.Lock()
	old := c.generation
	c.generation++
	c.mu.Unlock()
	c.invalidate(old)
	c.mu.Lock()
	valid := c.now().Before(c.expiry)
	c.expiry = c.now().Add(-time.Second)
	c.mu.Unlock()
	if !valid {
		t.Fatal("old failure invalidated new generation")
	}
	fresh := connect(t, c, address)
	if fresh.resumed {
		t.Fatal("expired state resumed")
	}
	exchange(t, fresh, 1)
	// Restart/unknown-ticket failure must invalidate the cache, then a new dial
	// performs a full handshake. No application payload is automatically retried.
	s.mu.Lock()
	clear(s.sessions)
	s.mu.Unlock()
	raw, e := net.Dial("tcp", address)
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(time.Second))
	bad, e := c.Handshake(context.Background(), raw)
	if e != nil {
		t.Fatal(e)
	}
	if !bad.resumed {
		t.Fatal("expected stale ticket attempt")
	}
	_, _ = bad.Write([]byte{1})
	if n, e := bad.Read(make([]byte, 1)); e == nil || n != 0 {
		t.Fatal("unknown ticket accepted")
	}
	next := connect(t, c, address)
	if next.resumed {
		t.Fatal("failed resume cache retained")
	}
	exchange(t, next, 1)
}

type memoryConn struct {
	bytes.Buffer
	output bytes.Buffer
}

func (c *memoryConn) Write(p []byte) (int, error)    { return c.output.Write(p) }
func (*memoryConn) Close() error                     { return nil }
func (*memoryConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*memoryConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*memoryConn) SetDeadline(time.Time) error      { return nil }
func (*memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*memoryConn) SetWriteDeadline(time.Time) error { return nil }
func TestRecordIntegrityNonceAndRekey(t *testing.T) {
	for _, aesMode := range []bool{true, false} {
		t.Run(fmt.Sprint(aesMode), func(t *testing.T) {
			key := bytes.Repeat([]byte{37}, 96)
			context := []byte("deterministic record context")
			for _, counter := range [][12]byte{{}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254}, {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254}, {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}} {
				transport := &memoryConn{}
				tx := &Conn{Conn: transport, tx: newCryptor(context, key, aesMode), united: key, aesMode: aesMode}
				tx.tx.counter = counter
				if _, e := tx.Write(bytes.Repeat([]byte{99}, 8193)); e != nil {
					t.Fatal(e)
				}
				wire := append([]byte(nil), transport.output.Bytes()...)
				input := &memoryConn{}
				input.Buffer.Write(wire)
				rx := &Conn{Conn: input, rx: newCryptor(context, key, aesMode), united: key, aesMode: aesMode}
				rx.rx.counter = counter
				got := make([]byte, 8193)
				if _, e := io.ReadFull(rx, got); e != nil || !bytes.Equal(got, bytes.Repeat([]byte{99}, 8193)) {
					t.Fatal("rekey/carry mismatch", e)
				}
				if counter == responseNonce && tx.tx.counter == counter {
					t.Fatal("no renewal")
				}
			}
			transport := &memoryConn{}
			tx := &Conn{Conn: transport, tx: newCryptor(context, key, aesMode), united: key, aesMode: aesMode}
			_, _ = tx.Write([]byte("authenticated secret payload"))
			wire := append([]byte(nil), transport.output.Bytes()...)
			for n := range wire {
				bad := append([]byte(nil), wire...)
				bad[n] ^= 128
				input := &memoryConn{}
				input.Buffer.Write(bad)
				rx := &Conn{Conn: input, rx: newCryptor(context, key, aesMode), united: key, aesMode: aesMode}
				if count, e := rx.Read(make([]byte, 100)); e == nil || count != 0 {
					t.Fatalf("tamper byte %d accepted", n)
				}
				if count, e := rx.Read(make([]byte, 100)); e == nil || count != 0 {
					t.Fatal("failed direction recovered")
				}
			}
			for n := 1; n < len(wire); n++ {
				input := &memoryConn{}
				input.Buffer.Write(wire[:n])
				rx := &Conn{Conn: input, rx: newCryptor(context, key, aesMode)}
				if count, e := rx.Read(make([]byte, 100)); e == nil || count != 0 {
					t.Fatal("truncated record accepted")
				}
			}
		})
	}
}

func TestRejectModeAndKeyMismatch(t *testing.T) {
	for _, pair := range [][2]string{{"native", "xorpub"}, {"native", "random"}, {"xorpub", "random"}, {"random", "native"}, {"random", "xorpub"}} {
		t.Run(strings.Join(pair[:], "-"), func(t *testing.T) {
			sc, cc := testConfigs(t, "x25519", pair[0], "1rtt", 1)
			cc.mode = pair[1]
			s, _ := NewServer(sc)
			c, _ := NewClient(cc)
			raw, e := net.Dial("tcp", serveEcho(t, s))
			if e != nil {
				t.Fatal(e)
			}
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(time.Second))
			conn, e := c.Handshake(context.Background(), raw)
			if e == nil {
				_, _ = conn.Write([]byte{1})
				n, readErr := conn.Read(make([]byte, 1))
				if n > 0 || readErr == nil {
					t.Fatal("mismatched mode accepted")
				}
			}
		})
	}
	sc, _ := testConfigs(t, "mlkem768", "native", "1rtt", 1)
	_, cc := testConfigs(t, "mlkem768", "native", "1rtt", 1)
	s, _ := NewServer(sc)
	c, _ := NewClient(cc)
	raw, e := net.Dial("tcp", serveEcho(t, s))
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(time.Second))
	if _, e = c.Handshake(context.Background(), raw); e == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestHandshakeCancellationAndBounds(t *testing.T) {
	sc, cc := testConfigs(t, "x25519", "native", "1rtt", 1)
	s, _ := NewServer(sc)
	c, _ := NewClient(cc)
	for _, server := range []bool{true, false} {
		a, b := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			var e error
			if server {
				_, e = s.Handshake(ctx, a)
			} else {
				_, e = c.Handshake(ctx, a)
			}
			done <- e
		}()
		cancel()
		select {
		case e := <-done:
			if e == nil {
				t.Fatal("canceled handshake succeeded")
			}
		case <-time.After(time.Second):
			t.Fatal("handshake blocked after cancellation")
		}
		a.Close()
		b.Close()
	}
	if _, e := NewClient(sc); !errors.Is(e, ErrConfig) {
		t.Fatal("role mismatch")
	}
	if _, e := NewServer(cc); !errors.Is(e, ErrConfig) {
		t.Fatal("role mismatch")
	}
}

func FuzzEncryptionConfig(f *testing.F) {
	for _, s := range []string{"none", "", method + ".native.600s.100-35-35.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", method + ".random.0rtt.100-35-35.CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = ParseClient(s); _, _ = ParseServer(s) })
}

func FuzzEncryptedRecord(f *testing.F) {
	f.Add([]byte{23, 3, 3, 0, 17})
	f.Add([]byte{})
	a := newCryptor([]byte("fuzz"), make([]byte, 96), true)
	h := header(20)
	f.Add(append(h, a.seal([]byte("seed"), h)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 70000 {
			return
		}
		input := &memoryConn{}
		input.Buffer.Write(b)
		c := &Conn{Conn: input, rx: newCryptor([]byte("fuzz"), make([]byte, 96), true)}
		_, _ = c.Read(make([]byte, 1))
	})
}

func TestHandshakeTamperAndRelayOrder(t *testing.T) {
	for _, auth := range []string{"x25519", "mlkem768"} {
		for _, mode := range []string{"native", "xorpub", "random"} {
			t.Run(auth+"/"+mode, func(t *testing.T) {
				sc, cc := testConfigs(t, auth, mode, "1rtt", 3)
				client, _ := NewClient(cc)
				capture := &memoryConn{}
				_, _ = client.Handshake(context.Background(), capture)
				hello := append([]byte(nil), capture.output.Bytes()...)
				positions := []int{0, 15, 16, 16 + sc.relaySize()/2, 15 + sc.relaySize(), 16 + sc.relaySize(), 33 + sc.relaySize(), 34 + sc.relaySize(), len(hello) - 1}
				for _, position := range positions {
					bad := append([]byte(nil), hello...)
					bad[position] ^= 1
					transport := &memoryConn{}
					transport.Buffer.Write(bad)
					server, _ := NewServer(sc)
					if _, e := server.Handshake(context.Background(), transport); e == nil {
						t.Fatalf("tampered handshake region %d accepted", position)
					}
					server.Close()
				}
				reversed := *sc
				reversed.keys = append([]key(nil), sc.keys...)
				reversed.keys[0], reversed.keys[1] = reversed.keys[1], reversed.keys[0]
				transport := &memoryConn{}
				transport.Buffer.Write(hello)
				server, _ := NewServer(&reversed)
				defer server.Close()
				if _, e := server.Handshake(context.Background(), transport); e == nil {
					t.Fatal("wrong relay chain order accepted")
				}
			})
		}
	}
}

func TestTicketReplayExpiryAndCacheBounds(t *testing.T) {
	sc, _ := testConfigs(t, "x25519", "native", "0rtt", 1)
	server, _ := NewServer(sc)
	defer server.Close()
	clock := time.Unix(1700000000, 0)
	server.now = func() time.Time { return clock }
	ticket, e := server.issue(bytes.Repeat([]byte{3}, 64))
	if e != nil {
		t.Fatal(e)
	}
	secret := bytes.Repeat([]byte{4}, 32)
	if _, ok := server.resume(ticket, secret); !ok {
		t.Fatal("initial resume rejected")
	}
	if _, ok := server.resume(ticket, secret); ok {
		t.Fatal("replay accepted")
	}
	clock = clock.Add(1000 * time.Second)
	if _, ok := server.resume(ticket, bytes.Repeat([]byte{5}, 32)); ok {
		t.Fatal("expired server ticket accepted")
	}
	for range maxSessions + 1 {
		if _, e := server.issue(make([]byte, 64)); e != nil {
			t.Fatal(e)
		}
	}
	if len(server.sessions) != maxSessions {
		t.Fatal("ticket cache bound")
	}
	ticket, e = server.issue(make([]byte, 64))
	if e != nil {
		t.Fatal(e)
	}
	for n := range maxResumes {
		secret := make([]byte, 32)
		secret[0] = byte(n)
		secret[1] = byte(n >> 8)
		if _, ok := server.resume(ticket, secret); !ok {
			t.Fatal("premature replay eviction")
		}
	}
	if _, ok := server.resume(ticket, bytes.Repeat([]byte{6}, 32)); ok {
		t.Fatal("replay set exceeded bound")
	}
	if _, ok := server.resume(ticket, make([]byte, 32)); ok {
		t.Fatal("replay entries removed without invalidating whole session")
	}
}

func TestConcurrentEncryptedWrites(t *testing.T) {
	for _, mode := range []string{"native", "xorpub", "random"} {
		t.Run(mode, func(t *testing.T) {
			sc, cc := testConfigs(t, "mlkem768", mode, "0rtt", 1)
			s, _ := NewServer(sc)
			client, _ := NewClient(cc)
			conn := connect(t, client, serveEcho(t, s))
			var wg sync.WaitGroup
			fail := make(chan error, 8)
			for n := range 8 {
				wg.Go(func() { _, e := conn.Write(bytes.Repeat([]byte{byte(n)}, 8193)); fail <- e })
			}
			got := make([]byte, 8*8193)
			if _, e := io.ReadFull(conn, got); e != nil {
				t.Fatal(e)
			}
			wg.Wait()
			close(fail)
			for e := range fail {
				if e != nil {
					t.Fatal(e)
				}
			}
			counts := [8]int{}
			for _, b := range got {
				if b > 7 {
					t.Fatal("write buffer corruption")
				}
				counts[b]++
			}
			for _, n := range counts {
				if n != 8193 {
					t.Fatal("concurrent writes lost bytes")
				}
			}
		})
	}
}

func TestMaximumReceiveRecordAndMixedRelay(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 96)
	for _, aesMode := range []bool{true, false} {
		for _, size := range []int{16623, 16624, 16625} {
			body := bytes.Repeat([]byte{9}, size)
			h := header(size + 16)
			a := newCryptor([]byte("max-receive"), key, aesMode)
			input := &memoryConn{}
			input.Buffer.Write(append(h, a.seal(body, h)...))
			conn := &Conn{Conn: input, rx: newCryptor([]byte("max-receive"), key, aesMode)}
			got := make([]byte, size)
			count, e := io.ReadFull(conn, got)
			if size > 16624 {
				if e == nil || count != 0 {
					t.Fatal("oversized record accepted")
				}
			} else if e != nil || !bytes.Equal(got, body) {
				t.Fatal("max record", e)
			}
		}
	}
	for _, mode := range []string{"native", "xorpub", "random"} {
		var sk, pk []string
		for _, auth := range []string{"x25519", "mlkem768", "x25519"} {
			server, client, e := Generate(auth, mode, "0rtt", "600s", "100-35-35")
			if e != nil {
				t.Fatal(e)
			}
			sk = append(sk, server[strings.LastIndex(server, ".")+1:])
			pk = append(pk, client[strings.LastIndex(client, ".")+1:])
		}
		sc, e := ParseServer(method + "." + mode + ".600s.100-35-35." + strings.Join(sk, "."))
		if e != nil {
			t.Fatal(e)
		}
		cc, e := ParseClient(method + "." + mode + ".0rtt.100-35-35." + strings.Join(pk, "."))
		if e != nil {
			t.Fatal(e)
		}
		server, _ := NewServer(sc)
		defer server.Close()
		client, _ := NewClient(cc)
		address := serveEcho(t, server)
		for range 2 {
			conn := connect(t, client, address)
			exchange(t, conn, 20000)
			conn.Close()
		}
	}
}

func TestPaddingPlanAndCancellation(t *testing.T) {
	for range 100 {
		sizes, gaps, total, e := paddingPlan(&Config{})
		if e != nil || len(sizes) != 2 || len(gaps) != 1 || sizes[0] < 111 || sizes[0] >= 1111 || sizes[1] < 0 || sizes[1] >= 3333 || gaps[0] < 0 || gaps[0] >= 111*time.Millisecond || total != sizes[0]+sizes[1] {
			t.Fatal("default padding bounds", e)
		}
	}
	cfg := &Config{padding: []tuple{{100, 35, 35}, {100, 500, 500}, {100, 35, 35}}}
	sizes, gaps, total, e := paddingPlan(cfg)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	e = sendHello(ctx, &memoryConn{}, []byte("hello"), paddingEnvelope(newCryptor([]byte("padding"), make([]byte, 32), true), total), sizes, gaps)
	if !errors.Is(e, context.DeadlineExceeded) || time.Since(started) > 300*time.Millisecond {
		t.Fatal("padding cancellation", e)
	}
}

func BenchmarkEncryptedRecord(b *testing.B) {
	transport := &memoryConn{}
	c := &Conn{Conn: transport, tx: newCryptor([]byte("benchmark"), make([]byte, 96), true), united: make([]byte, 96), aesMode: true}
	payload := make([]byte, 8192)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		transport.output.Reset()
		if _, e := c.Write(payload); e != nil {
			b.Fatal(e)
		}
	}
}

func TestStaticTypeAndIntermediateKeyRejection(t *testing.T) {
	for _, pair := range [][2]string{{"x25519", "mlkem768"}, {"mlkem768", "x25519"}, {"x25519", "x25519"}} {
		sc, _ := testConfigs(t, pair[0], "random", "1rtt", 1)
		_, cc := testConfigs(t, pair[1], "random", "1rtt", 1)
		client, _ := NewClient(cc)
		capture := &memoryConn{}
		_, _ = client.Handshake(context.Background(), capture)
		input := &memoryConn{}
		input.Buffer.Write(capture.output.Bytes())
		server, _ := NewServer(sc)
		if _, e := server.Handshake(context.Background(), input); e == nil {
			t.Fatal("wrong static key/type accepted")
		}
		server.Close()
	}
	sc, cc := testConfigs(t, "mlkem768", "random", "1rtt", 3)
	other, _ := testConfigs(t, "mlkem768", "random", "1rtt", 1)
	sc.keys[1] = other.keys[0]
	client, _ := NewClient(cc)
	capture := &memoryConn{}
	_, _ = client.Handshake(context.Background(), capture)
	input := &memoryConn{}
	input.Buffer.Write(capture.output.Bytes())
	server, _ := NewServer(sc)
	defer server.Close()
	if _, e := server.Handshake(context.Background(), input); e == nil {
		t.Fatal("wrong intermediate key accepted")
	}
}
