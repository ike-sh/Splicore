package native

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	maskcfg "github.com/ike-sh/Splicore/internal/splicore/domain/finalmask"
	streamcfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/engine/traffic"
	"github.com/ike-sh/Splicore/protocol/vless/wire"
)

type maskDeadlineEvent struct {
	operation string
	deadline  time.Time
}

type maskDeadlineConn struct {
	net.Conn
	mu     sync.Mutex
	events []maskDeadlineEvent
}

func (c *maskDeadlineConn) record(operation string, deadline time.Time) {
	c.mu.Lock()
	c.events = append(c.events, maskDeadlineEvent{operation, deadline})
	c.mu.Unlock()
}
func (c *maskDeadlineConn) SetDeadline(d time.Time) error {
	c.record("both", d)
	return c.Conn.SetDeadline(d)
}
func (c *maskDeadlineConn) SetReadDeadline(d time.Time) error {
	c.record("read", d)
	return c.Conn.SetReadDeadline(d)
}
func (c *maskDeadlineConn) SetWriteDeadline(d time.Time) error {
	c.record("write", d)
	return c.Conn.SetWriteDeadline(d)
}

// Exercise the actual native serve boundary using Pipes and a virtual clock.
// No deadline is supplied by the peer or by an isolated mask test.
func maskAdmissionServer(t *testing.T, masks []maskcfg.Mask) (*maskDeadlineConn, net.Conn, context.CancelFunc, <-chan time.Time) {
	t.Helper()
	a, b := net.Pipe()
	raw := &maskDeadlineConn{Conn: a}
	ctx, cancel := context.WithCancel(context.Background())
	h := &vlessHandle{ctx: ctx, transport: streamcfg.Config{Kind: "tcp"}, total: &traffic.Counter{},
		users: map[string]*traffic.Counter{"test": {}}, uuids: map[[16]byte]string{{}: "test"}, connections: map[net.Conn]bool{raw: true}}
	if masks != nil {
		h.transport.FinalMask = &maskcfg.Config{TCP: masks}
		if err := h.transport.ValidatePair("vless", "none"); err != nil {
			t.Fatal(err)
		}
	}
	h.admitted.Store(true)
	h.wg.Add(1)
	done := make(chan time.Time, 1)
	go func() {
		h.serve(raw)
		h.mu.Lock()
		remaining := len(h.connections)
		h.mu.Unlock()
		if remaining != 0 {
			t.Error("unauthenticated registry entry retained")
		}
		done <- time.Now()
	}()
	t.Cleanup(func() { cancel(); raw.Close(); b.Close() })
	return raw, b, cancel, done
}

func admissionHeader(settings string) maskcfg.Mask {
	return maskcfg.Mask{Type: "header-custom", Settings: json.RawMessage(settings)}
}

func TestVLESSFinalMaskAdmissionDeadline(t *testing.T) {
	for _, tc := range []struct {
		name, settings string
		input          string
		trickle        bool
		closeAfter     time.Duration
		cancelAfter    time.Duration
		want           time.Duration
	}{
		{"at-deadline", `{"servers":[[{"delay":5000,"type":"str","packet":"H"}]]}`, "", false, 0, 0, 5 * time.Second},
		{"over-deadline", `{"servers":[[{"delay":6000,"type":"str","packet":"H"}]]}`, "", false, 0, 0, 5 * time.Second},
		{"maximum-delay", `{"servers":[[{"delay":30000,"type":"str","packet":"H"}]]}`, "", false, 0, 0, 5 * time.Second},
		{"cumulative-delay", `{"servers":[[{"delay":3000},{"delay":3000,"type":"str","packet":"H"}]]}`, "", false, 0, 0, 5 * time.Second},
		{"missing-header", `{"clients":[[{"type":"str","packet":"HELLO"}]]}`, "", false, 0, 0, 5 * time.Second},
		{"partial-header-stall", `{"clients":[[{"type":"str","packet":"HELLO"}]]}`, "HE", false, 0, 0, 5 * time.Second},
		{"one-byte-trickle", `{"clients":[[{"type":"str","packet":"HELLO"}]]}`, "HELLO", true, 0, 0, 5 * time.Second},
		{"malformed-header", `{"clients":[[{"type":"str","packet":"HELLO"}]]}`, "XELLO", false, 0, 0, 0},
		{"delayed-error-response", `{"clients":[[{"type":"str","packet":"HELLO"}]],"errors":[[{"delay":6000,"type":"str","packet":"ERR"}]]}`, "XELLO", false, 0, 0, 5 * time.Second},
		{"peer-close", `{"clients":[[{"type":"str","packet":"HELLO"}]]}`, "", false, time.Second, 0, time.Second},
		{"context-cancel", `{"servers":[[{"delay":30000,"type":"str","packet":"H"}]]}`, "", false, 0, time.Second, time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				raw, peer, cancel, done := maskAdmissionServer(t, []maskcfg.Mask{admissionHeader(tc.settings)})
				stopInput := make(chan struct{})
				if tc.input != "" {
					go func() {
						if !tc.trickle {
							_, _ = io.WriteString(peer, tc.input)
							return
						}
						for i, b := range []byte(tc.input) {
							if i > 0 {
								timer := time.NewTimer(2 * time.Second)
								select {
								case <-timer.C:
								case <-stopInput:
									timer.Stop()
									return
								}
							}
							if _, err := peer.Write([]byte{b}); err != nil {
								return
							}
						}
					}()
				}
				if tc.closeAfter > 0 {
					go func() { time.Sleep(tc.closeAfter); peer.Close() }()
				}
				if tc.cancelAfter > 0 {
					go func() { time.Sleep(tc.cancelAfter); cancel() }()
				}
				elapsed := (<-done).Sub(start)
				close(stopInput)
				synctest.Wait()
				if elapsed != tc.want {
					t.Fatalf("native serve held unauthenticated connection for %v; want %v", elapsed, tc.want)
				}
				var b [1]byte
				if _, err := peer.Read(b[:]); err == nil {
					t.Fatal("peer was not closed")
				}
				raw.mu.Lock()
				defer raw.mu.Unlock()
				read, write := false, false
				for _, e := range raw.events {
					if e.deadline != start.Add(5*time.Second) {
						t.Fatal("absolute authentication deadline moved", e)
					}
					read = read || e.operation == "read"
					write = write || e.operation == "write"
				}
				if !read || !write {
					t.Fatal("mask deadline did not propagate read/write ownership", raw.events)
				}
			})
		})
	}
}

func TestVLESSFinalMaskAdmissionTransition(t *testing.T) {
	for _, delay := range []int{0, 4999} {
		t.Run(time.Duration(delay*int(time.Millisecond)).String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				settings, _ := json.Marshal(map[string]any{"servers": [][]map[string]any{{{"delay": delay, "type": "str", "packet": "H"}}}})
				start := time.Now()
				raw, peer, cancel, done := maskAdmissionServer(t, []maskcfg.Mask{admissionHeader(string(settings))})
				var b [1]byte
				if _, err := io.ReadFull(peer, b[:]); err != nil || b[0] != 'H' {
					t.Fatal("legal header before deadline rejected", err)
				}
				// Keep the historical shared absolute window through native auth.
				if err := wire.WriteRequest(peer, wire.Request{Command: wire.Mux}); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				raw.mu.Lock()
				for _, e := range raw.events {
					if !e.deadline.IsZero() && e.deadline != start.Add(5*time.Second) {
						t.Fatal("native auth inflated/reset the historical window", e)
					}
				}
				if len(raw.events) < 4 || !raw.events[len(raw.events)-1].deadline.IsZero() {
					t.Fatal("successful native auth did not clear mask deadline", raw.events)
				}
				raw.mu.Unlock()
				time.Sleep(10 * time.Second)
				select {
				case <-done:
					t.Fatal("authentication deadline leaked into the admitted stream")
				default:
				}
				cancel()
				<-done
			})
		})
	}
}

func TestVLESSFinalMaskAdmissionConcurrentCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		dones := make([]<-chan time.Time, 32)
		for i := range dones {
			_, peer, _, done := maskAdmissionServer(t, []maskcfg.Mask{admissionHeader(`{"clients":[[{"type":"str","packet":"HELLO"}]]}`)})
			dones[i] = done
			go func() { _, _ = peer.Write([]byte("H")) }()
		}
		for _, done := range dones {
			if elapsed := (<-done).Sub(start); elapsed != 5*time.Second {
				t.Fatal("concurrent admission escaped bound", elapsed)
			}
		}
	})
}

func TestVLESSFinalMaskAdmissionNativeRemainingBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		_, peer, _, done := maskAdmissionServer(t, []maskcfg.Mask{admissionHeader(`{"servers":[[{"delay":4999,"type":"str","packet":"H"}]]}`)})
		var header [1]byte
		if _, err := io.ReadFull(peer, header[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := peer.Write([]byte{0}); err != nil {
			t.Fatal(err)
		}
		if elapsed := (<-done).Sub(start); elapsed != 5*time.Second {
			t.Fatal("mask completion reset native authentication budget", elapsed)
		}
	})
}

func TestVLESSFinalMaskAdmissionNestedDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		masks := []maskcfg.Mask{
			admissionHeader(`{"servers":[[{"delay":3000,"type":"str","packet":"A"}]]}`),
			admissionHeader(`{"servers":[[{"delay":3000,"type":"str","packet":"B"}]]}`),
		}
		_, peer, _, done := maskAdmissionServer(t, masks)
		// Drain socket writes so only the nested masks' private delays bound
		// this case, rather than an unread Pipe write.
		go func() { _, _ = io.Copy(io.Discard, peer) }()
		if elapsed := (<-done).Sub(start); elapsed != 5*time.Second {
			t.Fatal("nested mask failed to inherit absolute deadline", elapsed)
		}
	})
}

func TestVLESSRAWAdmissionDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		raw, _, _, done := maskAdmissionServer(t, nil)
		if elapsed := (<-done).Sub(start); elapsed != 5*time.Second {
			t.Fatal("RAW native authentication deadline changed", elapsed)
		}
		if len(raw.events) != 1 || raw.events[0].operation != "both" || raw.events[0].deadline != start.Add(5*time.Second) {
			t.Fatal(raw.events)
		}
	})
}
