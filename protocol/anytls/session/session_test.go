package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/protocol/anytls/padding"
	"github.com/ike-sh/Splicore/protocol/anytls/wire"
)

func policy(t *testing.T, text string) *padding.Scheme {
	t.Helper()
	s, err := padding.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func testConfig(t *testing.T, v int) Config {
	return Config{Version: v, Padding: policy(t, "stop=0"), OpenTimeout: time.Second, WriteTimeout: time.Second, HeartbeatInterval: time.Second}
}
func eventually(t *testing.T, f func() bool) {
	t.Helper()
	end := time.Now().Add(2 * time.Second)
	for !f() {
		if time.Now().After(end) {
			t.Fatal("condition timed out")
		}
		time.Sleep(time.Millisecond)
	}
}
func pair(t *testing.T, cc, sc Config, handler func(*Stream)) (*Session, *Session) {
	t.Helper()
	a, b := net.Pipe()
	ready := make(chan *Session, 1)
	go func() {
		key, err := wire.ReadAuthentication(b)
		if err != nil || key != wire.PasswordKey("test") {
			b.Close()
			ready <- nil
			return
		}
		s, err := NewServer(b, sc, handler)
		if err != nil {
			ready <- nil
			return
		}
		ready <- s
	}()
	c, err := NewClient(a, wire.PasswordKey("test"), cc)
	if err != nil {
		t.Fatal(err)
	}
	s := <-ready
	if s == nil {
		t.Fatal("server setup")
	}
	t.Cleanup(func() { c.Close(); s.Close(); c.Wait(); s.Wait() })
	return c, s
}
func echo(st *Stream) {
	var initial [1]byte
	if _, err := io.ReadFull(st, initial[:]); err != nil {
		return
	}
	if st.Accept(nil) != nil {
		return
	}
	_, _ = io.Copy(st, st)
}
func exchange(st *Stream, data []byte) error {
	write := make(chan error, 1)
	go func() { _, err := st.Write(data); write <- err }()
	got := make([]byte, len(data))
	_, err := io.ReadFull(st, got)
	werr := <-write
	if err != nil {
		return err
	}
	if werr != nil {
		return werr
	}
	if !bytes.Equal(got, data) {
		return errors.New("payload crossover")
	}
	return nil
}

func TestVersionNegotiationAndReuse(t *testing.T) {
	for _, v := range [][2]int{{2, 2}, {2, 1}, {1, 2}, {1, 1}} {
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			c, s := pair(t, testConfig(t, v[0]), testConfig(t, v[1]), echo)
			for i := 1; i <= 20; i++ {
				st, err := c.Open(context.Background(), []byte{0})
				if err != nil {
					t.Fatal(err)
				}
				if st.ID() != uint32(i) {
					t.Fatal("nonmonotonic ID")
				}
				if err := exchange(st, bytes.Repeat([]byte{byte(i)}, 1000)); err != nil {
					t.Fatal(err)
				}
				st.Close()
			}
			want := 1
			if v[0] == 2 && v[1] == 2 {
				want = 2
			}
			if c.Version() != want || s.Version() != want {
				t.Fatalf("negotiated %d/%d", c.Version(), s.Version())
			}
			eventually(t, func() bool { return c.Active() == 0 && s.Active() == 0 })
		})
	}
}

func TestMultiplexPayloadIntegrity(t *testing.T) {
	for _, count := range []int{2, 10, 64} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			c, _ := pair(t, testConfig(t, 2), testConfig(t, 2), echo)
			var wg sync.WaitGroup
			errCh := make(chan error, count)
			ids := make(chan uint32, count)
			for i := 0; i < count; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					st, err := c.Open(context.Background(), []byte{0})
					if err != nil {
						errCh <- err
						return
					}
					defer st.Close()
					ids <- st.ID()
					for _, n := range []int{1, 97, 65535, 65536, 131111} {
						data := bytes.Repeat([]byte{byte(i + 1)}, n)
						if err = exchange(st, data); err != nil {
							errCh <- err
							return
						}
					}
					for j := 0; j < 32; j++ {
						if err = exchange(st, []byte{byte(i), byte(j)}); err != nil {
							errCh <- err
							return
						}
					}
				}(i)
			}
			wg.Wait()
			close(errCh)
			close(ids)
			for err := range errCh {
				t.Error(err)
			}
			seen := map[uint32]bool{}
			for id := range ids {
				if seen[id] {
					t.Fatal("ID alias")
				}
				seen[id] = true
			}
			if len(seen) != count {
				t.Fatal("missing stream")
			}
		})
	}
	c, _ := pair(t, testConfig(t, 2), testConfig(t, 2), echo)
	st, err := c.Open(context.Background(), []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err = exchange(st, bytes.Repeat([]byte("large duplex"), 300000)); err != nil {
		t.Fatal(err)
	}
}

func TestSYNACKFailureTimeoutAndIsolation(t *testing.T) {
	handler := func(st *Stream) {
		var initial [1]byte
		if _, err := io.ReadFull(st, initial[:]); err != nil {
			return
		}
		switch initial[0] {
		case 1:
			st.Accept(errors.New("refused"))
		case 2:
			<-st.Context().Done()
		default:
			st.Accept(nil)
			io.Copy(st, st)
		}
	}
	cc := testConfig(t, 2)
	cc.OpenTimeout = 50 * time.Millisecond
	c, _ := pair(t, cc, testConfig(t, 2), handler)
	healthy, err := c.Open(context.Background(), []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	defer healthy.Close()
	if _, err = c.Open(context.Background(), []byte{1}); !errors.Is(err, ErrOpen) {
		t.Fatalf("failure: %v", err)
	}
	if _, err = c.Open(context.Background(), []byte{2}); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("timeout: %v", err)
	}
	if err = exchange(healthy, []byte("unrelated survivor")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = c.Open(ctx, []byte{0}); err == nil {
		t.Fatal("cancel ignored")
	}
}

func TestFINDrainsAndShutdownReleases(t *testing.T) {
	c, _ := pair(t, testConfig(t, 2), testConfig(t, 2), func(st *Stream) { var b [1]byte; io.ReadFull(st, b[:]); st.Accept(nil); st.Write([]byte("retained")) })
	st, err := c.Open(context.Background(), []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return c.Active() == 0 })
	data, err := io.ReadAll(st)
	if err != nil || string(data) != "retained" {
		t.Fatalf("FIN lost data %q %v", data, err)
	}
	st.Close()
	if c.Err() != nil {
		t.Fatal(c.Err())
	}

	c, s := pair(t, testConfig(t, 2), testConfig(t, 2), echo)
	st, err = c.Open(context.Background(), []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	blocked := make(chan error, 1)
	go func() { var b [1]byte; _, err := st.Read(b[:]); blocked <- err }()
	s.Close()
	s.Wait()
	select {
	case err := <-blocked:
		if err == nil {
			t.Fatal("read survived session close")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked read leaked")
	}
	if _, err = st.Write([]byte{1}); err == nil {
		t.Fatal("write survived close")
	}
}

func TestReadDeadlineAndActiveWriteDeadline(t *testing.T) {
	c, _ := pair(t, testConfig(t, 2), testConfig(t, 2), echo)
	st, err := c.Open(context.Background(), []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	var b [1]byte
	if _, err = st.Read(b[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	st.SetReadDeadline(time.Time{})
	if err = exchange(st, []byte("recovered")); err != nil {
		t.Fatal(err)
	}
	a, peer := net.Pipe()
	defer peer.Close()
	cfg, _ := testConfig(t, 2).defaults()
	x := newSession(a, cfg, true, nil)
	x.start()
	t.Cleanup(func() { x.Close(); x.Wait() })
	x.mu.Lock()
	blockedStream := x.streamLocked(1)
	other := x.streamLocked(2)
	x.mu.Unlock()
	result := make(chan error, 1)
	go func() { _, err := blockedStream.Write([]byte("blocked socket")); result <- err }()
	eventually(t, func() bool { x.writeMu.Lock(); defer x.writeMu.Unlock(); return x.writing })
	other.SetWriteDeadline(time.Now())
	select {
	case err := <-result:
		t.Fatalf("other stream interrupted socket: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	blockedStream.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("active write deadline ignored")
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("active write stuck")
	}
}

func TestMalformedCommandsAndStreamBounds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		frames []wire.Frame
	}{
		{"syn-before-settings", []wire.Frame{{Command: wire.Open, Stream: 1}}},
		{"psh-before-syn", []wire.Frame{{Command: wire.Data, Stream: 1, Payload: []byte{1}}}},
		{"duplicate-syn", []wire.Frame{{Command: wire.Settings, Payload: []byte("v=1")}, {Command: wire.Open, Stream: 1}, {Command: wire.Open, Stream: 1}}},
		{"zero-id", []wire.Frame{{Command: wire.Data}}},
		{"client-server-settings", []wire.Frame{{Command: wire.ServerSettings, Payload: []byte("v=2")}}},
		{"v1-heartbeat", []wire.Frame{{Command: wire.Heartbeat}}},
		{"unknown-command", []wire.Frame{{Command: 255}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer b.Close()
			cfg, _ := testConfig(t, 1).defaults()
			s := newSession(a, cfg, false, func(st *Stream) { <-st.Context().Done() })
			defer s.Close()
			var err error
			for _, f := range tc.frames {
				err = s.dispatch(f)
				if err != nil {
					break
				}
			}
			if err == nil {
				t.Fatal("malformed command accepted")
			}
			s.shutdown(err)
			s.workers.Wait()
		})
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	cfg, _ := testConfig(t, 2).defaults()
	s := newSession(a, cfg, true, nil)
	s.lastID = math.MaxUint32
	if _, err := s.Open(context.Background(), []byte{0}); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	s.mu.Lock()
	slow := s.streamLocked(1)
	good := s.streamLocked(2)
	s.lastID = 2
	s.mu.Unlock()
	// Use a draining peer so the stream-local FIN can be sent.
	go io.Copy(io.Discard, b)
	for i := 0; i < cfg.MaxStreamBuffer/65535+2; i++ {
		if err := s.dispatch(wire.Frame{Command: wire.Data, Stream: 1, Payload: make([]byte, 65535)}); err != nil {
			t.Fatal(err)
		}
	}
	if !slow.closed || !errors.Is(slow.err, ErrLimit) || s.Active() != 1 {
		t.Fatal("slow consumer not isolated")
	}
	if err := s.dispatch(wire.Frame{Command: wire.Data, Stream: 2, Payload: []byte("ok")}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(good, buf); err != nil || string(buf) != "ok" {
		t.Fatal("healthy stream damaged")
	}
	if err := s.dispatch(wire.Frame{Command: wire.Finish, Stream: 999}); err != nil {
		t.Fatal("unknown FIN")
	}
	s.Close()
}

func TestHeartbeatResponseFailureAndV1Silence(t *testing.T) {
	cc := testConfig(t, 2)
	cc.HeartbeatInterval = 10 * time.Millisecond
	cc.HeartbeatTimeout = 30 * time.Millisecond
	c, _ := pair(t, cc, testConfig(t, 2), echo)
	st, err := c.Open(context.Background(), []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	time.Sleep(80 * time.Millisecond)
	if c.Err() != nil {
		t.Fatal("heartbeat response failed", c.Err())
	}
	// A v2 peer reads requests but never responds.
	a, b := net.Pipe()
	defer b.Close()
	cfg, _ := cc.defaults()
	silent := newSession(a, cfg, true, nil)
	silent.version = 2
	silent.start()
	t.Cleanup(func() { silent.Close(); silent.Wait() })
	requests := make(chan wire.Frame, 4)
	go func() {
		for {
			f, e := wire.ReadFrame(b)
			if e != nil {
				return
			}
			requests <- f
		}
	}()
	select {
	case f := <-requests:
		if f.Command != wire.Heartbeat {
			t.Fatal(f)
		}
	case <-time.After(time.Second):
		t.Fatal("no heartbeat")
	}
	select {
	case <-silent.Done():
	case <-time.After(time.Second):
		t.Fatal("missing liveness timeout")
	}
	if !errors.Is(silent.Err(), os.ErrDeadlineExceeded) {
		t.Fatal(silent.Err())
	}
	v1cfg := cc
	v1cfg.Version = 1
	c, _ = pair(t, cc, v1cfg, echo)
	st, err = c.Open(context.Background(), []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	if c.Err() != nil || c.Version() != 1 {
		t.Fatal("v2 commands reached v1")
	}
	st.Close()
}

func TestAlertAndInvalidPaddingUpdate(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	cfg, _ := testConfig(t, 2).defaults()
	s := newSession(a, cfg, true, nil)
	defer s.Close()
	if err := s.dispatch(wire.Frame{Command: wire.PaddingUpdate, Payload: []byte("stop=-1")}); err == nil {
		t.Fatal("bad update")
	}
	if err := s.dispatch(wire.Frame{Command: wire.Alert, Payload: []byte("bounded alert")}); !errors.Is(err, ErrAlert) {
		t.Fatal(err)
	}
}
