package encryption

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func timingPadding(ms int) string {
	fields := []string{"100-35-35"}
	for ms > 0 {
		gap := min(ms, maxPaddingGapMS)
		fields = append(fields, fmt.Sprintf("100-%d-%d", gap, gap), "100-35-35")
		ms -= gap
	}
	return strings.Join(fields, ".")
}

func timingConfigs(t *testing.T, auth, mode, policy, padding string, keys int) (*Config, *Config) {
	t.Helper()
	var sk, pk []string
	for range keys {
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

func TestPaddingTimingBounds(t *testing.T) {
	for _, row := range []struct {
		padding   string
		low, high time.Duration
	}{
		{"", 0, 110 * time.Millisecond},
		{"100-35-35", 0, 0},
		{"100-35-35.100-900-900", 900 * time.Millisecond, 900 * time.Millisecond},
		{"100-35-35.99-900-1000", 900 * time.Millisecond, 999 * time.Millisecond},
		{"100-35-35.0-900-1000", 0, 999 * time.Millisecond},
		{"100-35-35.50-0-1", 0, 0},
		{timingPadding(15000), 15 * time.Second, 15 * time.Second},
	} {
		t.Run(row.padding, func(t *testing.T) {
			sk, _, e := Generate("x25519", "native", "1rtt", "600s", row.padding)
			if e != nil {
				t.Fatal(e)
			}
			cfg, e := ParseServer(sk)
			if e != nil {
				t.Fatal(e)
			}
			lo, hi := cfg.PaddingDelayBounds()
			if lo != row.low || hi != row.high || cfg.handshakeTimeout() != activeHandshakeBudget+peerPaddingBudget+hi {
				t.Fatalf("bounds %v..%v, timeout %v", lo, hi, cfg.handshakeTimeout())
			}
		})
	}
	for _, pad := range []string{timingPadding(16000), "100-35-35.100-1001-1001", "100-35-35.100-9223372036854775807-9223372036854775807"} {
		if _, _, e := Generate("x25519", "native", "1rtt", "600s", pad); e == nil {
			t.Fatal("unbounded padding accepted")
		}
	}
}

func timingTCP(t *testing.T, sc, cc *Config, iterations int) {
	t.Helper()
	server, e := NewServer(sc)
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	client, e := NewClient(cc)
	if e != nil {
		t.Fatal(e)
	}
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	for iteration := range iterations {
		raw, e := net.Dial("tcp", l.Addr().String())
		if e != nil {
			t.Fatal(e)
		}
		peer, e := l.Accept()
		if e != nil {
			raw.Close()
			t.Fatal(e)
		}
		raw.SetDeadline(time.Now().Add(40 * time.Second))
		peer.SetDeadline(time.Now().Add(40 * time.Second))
		done := make(chan error, 1)
		started := time.Now()
		go func() {
			defer peer.Close()
			c, e := server.Handshake(context.Background(), peer)
			if e == nil {
				if c.resumed != (cc.resume && iteration > 0) {
					e = fmt.Errorf("server resume path mismatch")
				} else {
					_, e = io.Copy(c, c)
				}
			}
			done <- e
		}()
		c, err := client.Handshake(context.Background(), raw)
		if err == nil {
			if c.resumed != (cc.resume && iteration > 0) {
				err = fmt.Errorf("client resume path mismatch")
			} else {
				exchange(t, c, 32771)
			}
		}
		raw.Close()
		serverErr := <-done
		if err != nil || serverErr != nil {
			t.Fatal(err, serverErr)
		}
		t.Logf("full=%v resumed=%v handshake+application=%v", iteration == 0, c.resumed, time.Since(started))
	}
}

func TestPaddingTimingTCPBoundaries(t *testing.T) {
	for _, delay := range []int{0, 100, 4500, 4900, 5000, 5100, 5400, 6000, 15000} {
		t.Run(fmt.Sprint(delay), func(t *testing.T) {
			t.Parallel()
			sc, cc := timingConfigs(t, "x25519", "native", "1rtt", timingPadding(delay), 1)
			timingTCP(t, sc, cc, 1)
		})
	}
	t.Run("original-six-900", func(t *testing.T) {
		t.Parallel()
		sc, cc := timingConfigs(t, "x25519", "native", "1rtt", "100-35-35"+strings.Repeat(".100-900-900.100-35-35", 6), 1)
		timingTCP(t, sc, cc, 1)
	})
	for _, tc := range []struct {
		name, padding string
		keys          int
	}{
		{"range-crosses-old-five-seconds", "100-35-35" + strings.Repeat(".50-667-1000.100-35-35", 6), 1},
		{"mandatory-range-crosses-old-five-seconds", "100-35-35" + strings.Repeat(".100-667-1000.100-35-35", 6), 3},
		{"max-chain", timingPadding(5400), 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sc, cc := timingConfigs(t, "mlkem768", "random", "0rtt", tc.padding, tc.keys)
			timingTCP(t, sc, cc, 2)
		})
	}
}

func TestPaddingTimingGeneratorModes(t *testing.T) {
	for _, auth := range []string{"x25519", "mlkem768"} {
		for _, mode := range []string{"native", "xorpub", "random"} {
			for _, policy := range []string{"1rtt", "0rtt"} {
				t.Run(auth+"/"+mode+"/"+policy, func(t *testing.T) {
					sc, cc := timingConfigs(t, auth, mode, policy, timingPadding(50), 1)
					timingTCP(t, sc, cc, 2)
				})
			}
		}
	}
}

func TestPaddingTimingStalledPeer(t *testing.T) {
	t.Parallel()
	sc, _ := timingConfigs(t, "x25519", "native", "1rtt", timingPadding(0), 1)
	s, _ := NewServer(sc)
	defer s.Close()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	started := time.Now()
	_, err := s.Handshake(context.Background(), a)
	elapsed := time.Since(started)
	if err == nil || elapsed < sc.handshakeTimeout() || elapsed > sc.handshakeTimeout()+3*time.Second {
		t.Fatalf("unbounded/early stall: %v %v", elapsed, err)
	}
	t.Logf("stalled peer timed out at %v (policy %v)", elapsed, sc.handshakeTimeout())
}

func TestPaddingTimingCancelAndDeadline(t *testing.T) {
	sc, cc := timingConfigs(t, "x25519", "random", "0rtt", timingPadding(15000), 1)
	s, _ := NewServer(sc)
	defer s.Close()
	c, _ := NewClient(cc)
	for cycle := range 24 {
		a, b := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 2)
		go func() { _, err := s.Handshake(ctx, a); done <- err }()
		go func() { _, err := c.Handshake(ctx, b); done <- err }()
		time.Sleep(time.Millisecond)
		cancel()
		for range 2 {
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled handshake succeeded")
				}
			case <-time.After(time.Second):
				t.Fatalf("cycle %d leaked", cycle)
			}
		}
		a.Close()
		b.Close()
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(20 * time.Millisecond))
	started := time.Now()
	if _, err := s.Handshake(context.Background(), a); err == nil || time.Since(started) > time.Second {
		t.Fatal("transport deadline replaced", err)
	}
}
