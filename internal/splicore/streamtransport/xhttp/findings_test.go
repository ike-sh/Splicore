package xhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestXHTTPReservedMetadataAmbiguity(t *testing.T) {
	c := cfg.Config{Kind: "xhttp", Path: "/test", XHTTP: &cfg.XHTTP{Mode: "packet-up", SessionPlacement: "header", SequencePlacement: "header", DataPlacement: "header", PaddingObfs: true, PaddingPlacement: "header"}}
	makeRequest := func() *http.Request {
		r := httptest.NewRequest("POST", "http://example.test/test", nil)
		if e := decorate(r, c, "Exact-ID", "0", false, rand.Reader); e != nil {
			t.Fatal(e)
		}
		if e := placePacket(r, c, []byte("payload"), rand.Reader); e != nil {
			t.Fatal(e)
		}
		return r
	}
	for _, key := range []string{"X-Session", "X-Seq", "X-Data-0", "X-Padding"} {
		for _, form := range []string{"repeat", "case", "multi", "comma"} {
			t.Run(key+"/"+form, func(t *testing.T) {
				r := makeRequest()
				v := r.Header.Get(key)
				switch form {
				case "repeat":
					r.Header.Add(key, v)
				case "case":
					r.Header[strings.ToLower(key)] = []string{v}
				case "multi":
					r.Header[key] = []string{v, "other"}
				case "comma":
					r.Header.Set(key, v+","+v)
				}
				// Padding is a value-length envelope, never a list; a comma changes its
				// token contents. Association/chunk metadata must reject every list form.
				if _, _, e := parseEnvelope(r, c); e == nil {
					t.Fatal("ambiguous metadata accepted")
				}
			})
		}
		for _, variant := range []string{key, strings.ToLower(key), strings.ToUpper(key), "x" + strings.ToUpper(key[1:])} {
			t.Run("single/"+variant, func(t *testing.T) {
				r := makeRequest()
				v := r.Header.Get(key)
				delete(r.Header, key)
				r.Header[variant] = []string{v}
				sid, seq, e := parseEnvelope(r, c)
				if e != nil || sid != "Exact-ID" || seq != "0" {
					t.Fatal(sid, seq, e)
				}
				b, e := packetPayload(r, c)
				if e != nil || string(b) != "payload" {
					t.Fatal(string(b), e)
				}
			})
		}
	}
	for _, name := range []string{"X-Data-1", "X-Data-00", "X-Data-4096", "X-Data-invalid"} {
		r := makeRequest()
		delete(r.Header, "X-Data-0")
		r.Header.Set(name, "QQ")
		if _, e := packetPayload(r, c); e == nil {
			t.Fatal("ambiguous/gapped data namespace", name)
		}
	}
	r := makeRequest()
	r.Header.Set("X-Application", "custom")
	if _, _, e := parseEnvelope(r, c); e != nil {
		t.Fatal(e)
	}
	r.Host = "other.test"
	c.Host = "example.test"
	if _, _, e := parseEnvelope(r, c); e == nil {
		t.Fatal("authority mismatch")
	}
}

type failEntropy struct{}

func (failEntropy) Read([]byte) (int, error) { return 0, errors.New("entropy failed") }
func identityClient(r io.Reader) *Client {
	return &Client{config: cfg.Config{Kind: "xhttp"}, entropy: r, sessions: map[*clientSession]bool{}, identities: map[string]*clientSession{}}
}
func reserve(t *testing.T, c *Client) *clientSession {
	t.Helper()
	s := &clientSession{}
	if e := c.reserveSession(s, "packet-up"); e != nil {
		t.Fatal(e)
	}
	c.workers.Done()
	return s
}
func TestXHTTPSessionSecureGenerationAndCollision(t *testing.T) {
	cl, e := NewClient((&net.Dialer{}).DialContext, "127.0.0.1:1", cfg.Config{Kind: "xhttp"}, Security{}, nil)
	if e != nil {
		t.Fatal(e)
	}
	if cl.entropy != rand.Reader {
		t.Fatal("default source is not crypto/rand.Reader")
	}
	cl.Close()
	zero := make([]byte, 16)
	one := bytes.Repeat([]byte{1}, 16)
	c := identityClient(bytes.NewReader(append(append(append([]byte{}, zero...), zero...), one...)))
	first := reserve(t, c)
	second := reserve(t, c)
	if first.id == second.id || c.identities[first.id] != first || c.identities[second.id] != second {
		t.Fatal("collision overwrote existing session")
	}
	if len(first.id) != 36 || first.id[14] != '4' || !strings.ContainsRune("89ab", rune(first.id[19])) {
		t.Fatal("UUIDv4 shape")
	}
	c.entropy = bytes.NewReader(make([]byte, 16*sessionIDAttempts))
	if e := c.reserveSession(&clientSession{}, "packet-up"); e == nil {
		t.Fatal("collision retry exhaustion accepted")
	}
	if len(c.sessions) != 2 || c.identities[first.id] != first {
		t.Fatal("exhaustion altered existing registry")
	}
	c.entropy = failEntropy{}
	if e := c.reserveSession(&clientSession{}, "packet-up"); e == nil {
		t.Fatal("entropy error ignored")
	}
	for _, x := range []cfg.XHTTP{{}, {SessionTable: "Base62", SessionLength: cfg.Range{32, 32}}, {SessionTable: "number", SessionLength: cfg.Range{37, 40}}} {
		seen := map[string]bool{}
		for i := 0; i < 4096; i++ {
			id, e := sessionToken(x, rand.Reader)
			if e != nil || seen[id] {
				t.Fatal("batch uniqueness", e)
			}
			seen[id] = true
			if x.SessionTable != "" && (len(id) < int(x.SessionLength.Min) || len(id) > int(x.SessionLength.Max)) {
				t.Fatal("generation length")
			}
		}
	}
}

func TestXHTTPConcurrentIdentityReservation(t *testing.T) {
	c := identityClient(rand.Reader)
	var group sync.WaitGroup
	errs := make(chan error, 512)
	for i := 0; i < 512; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if e := c.reserveSession(&clientSession{}, "packet-up"); e != nil {
				errs <- e
			} else {
				c.workers.Done()
			}
		}()
	}
	group.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	if len(c.sessions) != 512 || len(c.identities) != 512 {
		t.Fatal("concurrent registry replacement")
	}
	if e := c.reserveSession(&clientSession{}, "packet-up"); e == nil {
		t.Fatal("registry bound")
	}
}

type admissionBase struct{ net.Listener }

func (admissionBase) Addr() net.Addr { return address("test-listener") }
func (admissionBase) Close() error   { return nil }
func admissionListener() *Listener {
	ctx, cancel := context.WithCancel(context.Background())
	return &Listener{base: admissionBase{}, config: cfg.Config{Kind: "xhttp", Path: "/ready", XHTTP: &cfg.XHTTP{Padding: cfg.Range{1, 1}}}, ctx: ctx, cancel: cancel, server: &http.Server{}, sessions: map[string]*session{}, connections: map[net.Conn]bool{}, queue: make(chan net.Conn, 64), entropy: rand.Reader}
}

type readyResponse struct {
	*httptest.ResponseRecorder
	flushed chan struct{}
	once    sync.Once
}

func (r *readyResponse) Flush() { r.ResponseRecorder.Flush(); r.once.Do(func() { close(r.flushed) }) }
func downRequest(t *testing.T, l *Listener, id string) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest("GET", "http://example.test/ready/", nil).WithContext(ctx)
	if e := decorate(r, l.config, id, "", false, rand.Reader); e != nil {
		t.Fatal(e)
	}
	w := &readyResponse{ResponseRecorder: httptest.NewRecorder(), flushed: make(chan struct{})}
	done := make(chan struct{})
	go func() { l.ServeHTTP(w, r); close(done) }()
	<-w.flushed
	return cancel, done
}

func TestXHTTPMixedInboundIdentityAndGeneratedCollision(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := admissionListener()
		defer l.Close()
		for _, id := range []string{"1", "AbC", "abc", strings.Repeat("z", 256), "AbC0"} {
			r := httptest.NewRequest("GET", "http://example.test/ready/", nil)
			decorate(r, l.config, id, "", false, rand.Reader)
			parsed, _, e := parseEnvelope(r, l.config)
			if e != nil || parsed != id {
				t.Fatal("valid reference identity rejected", id, e)
			}
			s, e := l.allocate(parsed)
			if e != nil || s.id != id {
				t.Fatal(e)
			}
			again, _ := l.allocate(id)
			if s != again {
				t.Fatal("HTTP leg association lost")
			}
		}
		if l.sessions["AbC"] == l.sessions["abc"] || l.sessions["AbC"] == l.sessions["AbC0"] {
			t.Fatal("non-exact lookup")
		}
		l.entropy = bytes.NewReader(make([]byte, 16))
		first, e := l.allocateGenerated()
		if e != nil {
			t.Fatal(e)
		}
		l.entropy = bytes.NewReader(append(make([]byte, 16), bytes.Repeat([]byte{1}, 16)...))
		second, e := l.allocateGenerated()
		if e != nil || first == second || l.sessions[first.id] != first {
			t.Fatal("generated collision overwrote live inbound", e)
		}
		l.entropy = bytes.NewReader(make([]byte, 16*sessionIDAttempts))
		if _, e := l.allocateGenerated(); e == nil {
			t.Fatal("inbound retry exhaustion")
		}
		if l.sessions[first.id] != first {
			t.Fatal("original inbound lost")
		}
	})
}

func TestXHTTPDataReadyNativeAdmission(t *testing.T) {
	for _, delay := range []time.Duration{0, 30 * time.Millisecond, 6 * time.Second, time.Duration(cfg.XHTTPMaxFirstPacketIntervalMs) * time.Millisecond} {
		t.Run(delay.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				l := admissionListener()
				defer l.Close()
				cancel, done := downRequest(t, l, "delayed")
				defer cancel()
				accepted := make(chan net.Conn, 1)
				go func() {
					c, e := l.Accept()
					if e == nil {
						c.SetDeadline(time.Now().Add(5 * time.Second))
						accepted <- c
					}
				}()
				synctest.Wait()
				select {
				case <-accepted:
					t.Fatal("native admission started before data")
				default:
				}
				time.Sleep(delay)
				synctest.Wait()
				select {
				case <-accepted:
					t.Fatal("delayed stream admitted without bytes")
				default:
				}
				original := []byte("first bytes preserved exactly")
				l.mu.Lock()
				s := l.sessions["delayed"]
				l.mu.Unlock()
				if e := s.enqueue(0, original); e != nil {
					t.Fatal(e)
				}
				c := <-accepted
				got := make([]byte, len(original))
				if _, e := io.ReadFull(c, got); e != nil || !bytes.Equal(got, original) {
					t.Fatal("native first read", e, string(got))
				}
				c.Close()
				<-done
			})
		})
	}
}

func TestXHTTPAdmissionTimeoutAndCloseCleanup(t *testing.T) {
	for _, closeEarly := range []bool{false, true} {
		t.Run(fmt.Sprint(closeEarly), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				l := admissionListener()
				defer l.Close()
				cancel, done := downRequest(t, l, "no-data")
				defer cancel()
				synctest.Wait()
				if closeEarly {
					cancel()
				} else {
					time.Sleep(associationTimeout + time.Nanosecond)
				}
				<-done
				synctest.Wait()
				l.mu.Lock()
				remaining, pending := len(l.sessions), l.pending
				l.mu.Unlock()
				if remaining != 0 || pending != 0 || len(l.queue) != 0 {
					t.Fatal("unready session cleanup", remaining, pending)
				}
			})
		})
	}
}

func TestXHTTPConcurrentDelayedAdmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := admissionListener()
		defer l.Close()
		done := []<-chan struct{}{}
		for i := 0; i < 8; i++ {
			cancel, d := downRequest(t, l, fmt.Sprint(i))
			defer cancel()
			done = append(done, d)
		}
		time.Sleep(6 * time.Second)
		synctest.Wait()
		if len(l.queue) != 0 {
			t.Fatal("premature concurrent admission")
		}
		for i := 0; i < 8; i++ {
			l.mu.Lock()
			s := l.sessions[fmt.Sprint(i)]
			l.mu.Unlock()
			if e := s.enqueue(0, []byte(fmt.Sprint(i))); e != nil {
				t.Fatal(e)
			}
		}
		seen := map[string]bool{}
		for i := 0; i < 8; i++ {
			c, e := l.Accept()
			if e != nil {
				t.Fatal(e)
			}
			b := make([]byte, 1)
			if _, e := io.ReadFull(c, b); e != nil {
				t.Fatal(e)
			}
			if seen[string(b)] {
				t.Fatal("cross-session data")
			}
			seen[string(b)] = true
			c.Close()
		}
		for _, d := range done {
			<-d
		}
	})
}

func TestXHTTPLegDialSecuritySharedBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := net.Pipe()
		defer b.Close()
		cl := &Client{target: "test", dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			time.Sleep(4 * time.Second)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return a, nil
		}, security: Security{Handshake: func(ctx context.Context, c net.Conn) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }}}
		e := &httpEntry{pool: &connectionPool{owner: cl}, sockets: map[net.Conn]bool{}}
		started := time.Now()
		if _, err := e.connect(context.Background(), true); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		if time.Since(started) != cfg.XHTTPLegAdmissionTimeout || len(e.sockets) != 0 {
			t.Fatal("separate/unbounded dial/security budgets")
		}
		if _, err := b.Write([]byte("closed")); err == nil {
			t.Fatal("failed admission retained socket")
		}
	})
}

func TestXHTTPDuplicateAssociationValues(t *testing.T) {
	for _, place := range []string{"query", "cookie"} {
		c := cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{SessionPlacement: place, SequencePlacement: place}}
		for _, key := range []string{"x_session", "x_seq"} {
			r := httptest.NewRequest("POST", "http://example.test/", nil)
			decorate(r, c, "id", "0", false, rand.Reader)
			if place == "query" {
				q := r.URL.Query()
				q.Add(key, "other")
				r.URL.RawQuery = q.Encode()
			} else {
				r.AddCookie(&http.Cookie{Name: key, Value: "other"})
			}
			if _, _, err := parseEnvelope(r, c); err == nil {
				t.Fatal("duplicate association values", place, key)
			}
		}
	}
}
