package native

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	ss "github.com/ike-sh/Splicore/internal/splicore/protocol/shadowsocks"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/shadowsocks/wire"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func ssFDs(t *testing.T) int {
	t.Helper()
	files, e := os.ReadDir("/proc/self/fd")
	if e != nil {
		t.Fatal(e)
	}
	n := 0
	for _, f := range files {
		_, e := os.Readlink(filepath.Join("/proc/self/fd", f.Name()))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			t.Fatal(e)
		}
		n++
	}
	return n
}
func TestShadowsocksAbuseAndUDPChurnResources(t *testing.T) {
	if os.Getenv("SPLICORE_SS_RESOURCE_CHILD") != "1" {
		// Other protocol tests may be retiring asynchronous library workers. A
		// fresh copy of this same test binary gives comparable stopped states.
		exe, e := os.Executable()
		if e != nil {
			t.Fatal(e)
		}
		command := exec.Command(exe, "-test.run=^TestShadowsocksAbuseAndUDPChurnResources$", "-test.v", "-test.timeout=40s")
		command.Env = append(os.Environ(), "SPLICORE_SS_RESOURCE_CHILD=1")
		out, e := command.CombinedOutput()
		t.Logf("%s", out)
		if e != nil {
			t.Fatal("isolated resource test", e)
		}
		return
	}
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	target := shadowsocksUDPFixture(t)
	baseFD, baseGo := ssFDs(t), runtime.NumGoroutine()
	peakFD, peakGo := baseFD, baseGo
	for _, method := range []string{"aes-128-gcm", "2022-blake3-aes-128-gcm"} {
		in := shadowsocksIntent(t, method, method != "aes-128-gcm")
		prepared, e := NewShadowsocksCompiler().Compile(ctx, in)
		if e != nil {
			t.Fatal(e)
		}
		h := prepared.(*shadowsocksHandle)
		defer h.Close(context.Background())
		if e = h.Start(ctx); e != nil {
			t.Fatal(e)
		}
		h.Activate()
		address := net.JoinHostPort(h.endpoint.Host, fmt.Sprint(h.endpoint.Port))
		pc, e := net.Dial("udp", address)
		if e != nil {
			t.Fatal(e)
		}
		for range 2000 {
			if _, e = pc.Write([]byte("synthetic malformed authenticated-no")); e != nil {
				t.Fatal(e)
			}
		}
		pc.Close()
		for range 128 {
			raw, e := net.Dial("tcp", address)
			if e != nil {
				t.Fatal(e)
			}
			raw.Write(make([]byte, 128))
			raw.Close()
		}
		// Authenticated churn, independent source/session IDs, real routing sockets.
		keys, e := wire.Keys(method, ss.Material(in.Credentials[0].Payload))
		if e != nil {
			t.Fatal(e)
		}
		if h.identity != nil {
			keys = append([]*wire.Key{h.identity}, keys...)
		}
		for cycle := range 4 {
			for range 64 {
				raw, e := net.Dial("udp", address)
				if e != nil {
					t.Fatal(e)
				}
				raw.SetDeadline(time.Now().Add(3 * time.Second))
				session, e := wire.SessionID()
				if e != nil {
					t.Fatal(e)
				}
				body, e := wire.EncodePacket(keys, wire.Datagram{Session: session, Destination: target, Payload: []byte("authenticated-churn")}, false, time.Now())
				if e != nil {
					t.Fatal(e)
				}
				if _, e = raw.Write(body); e != nil {
					t.Fatal(e)
				}
				reply := make([]byte, 65535)
				n, e := raw.Read(reply)
				if e != nil {
					t.Fatal(e)
				}
				p, e := wire.DecodePacket([]*wire.Key{keys[len(keys)-1]}, nil, reply[:n], true, session, wire.NewSaltCache(4, time.Minute), time.Now())
				if e != nil || string(p.Payload) != "authenticated-churn" {
					t.Fatal(e)
				}
				raw.Close()
			}
			peakFD = max(peakFD, ssFDs(t))
			peakGo = max(peakGo, runtime.NumGoroutine())
			h.mu.Lock()
			count := len(h.sessions)
			for _, s := range h.sessions {
				s.mu.Lock()
				s.last = time.Now().Add(-100 * time.Second)
				s.mu.Unlock()
			}
			h.mu.Unlock()
			if count > 128 {
				t.Fatal("association cap")
			}
			// Exercise the actual expiry worker with aged test sessions. Readiness
			// observation only; no sleeping or retrying failed payloads.
			deadline := time.Now().Add(3 * time.Second)
			for {
				h.mu.Lock()
				count = len(h.sessions)
				h.mu.Unlock()
				if count == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("expiry did not release associations")
				}
				runtime.Gosched()
			}
			t.Logf("method=%s churn=%d admitted=64 expired=0 FD=%d goroutines=%d", method, cycle+1, ssFDs(t), runtime.NumGoroutine())
		}
		closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		e = h.Close(closeCtx)
		cancel()
		if e != nil {
			t.Fatal(e)
		}
		if h.Stats().Active != 0 {
			t.Fatal("active residue")
		}
		if ssFDs(t) != baseFD {
			t.Fatalf("FD retained start=%d end=%d", baseFD, ssFDs(t))
		}
	}
	t.Logf("malformed UDP=4000 malformed/auth-failure TCP=256 authenticated UDP associations=512 start FD=%d goroutines=%d peak FD=%d goroutines=%d end FD=%d goroutines=%d", baseFD, baseGo, peakFD, peakGo, ssFDs(t), runtime.NumGoroutine())
}
