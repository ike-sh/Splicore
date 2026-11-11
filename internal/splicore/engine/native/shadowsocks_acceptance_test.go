package native

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	ss "github.com/ike-sh/Splicore/internal/splicore/protocol/shadowsocks"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/shadowsocks/wire"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

type ssRequestCapture struct {
	net.Conn
	requests bytes.Buffer // Owned by the single test writer; read after that writer returns.
}

func (c *ssRequestCapture) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.requests.Write(b[:n])
	return n, err
}

func TestShadowsocksAuthenticatedReplayAfterRestart(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "2022-blake3-aes-128-gcm"} {
		t.Run(method, func(t *testing.T) {
			ctx := underlay.WithFactory(context.Background(), underlay.New())
			in := shadowsocksIntent(t, method, false)
			compiler := NewShadowsocksCompiler()
			start := func() *shadowsocksHandle {
				t.Helper()
				p, err := compiler.Compile(ctx, in)
				if err != nil {
					t.Fatal(err)
				}
				h := p.(*shadowsocksHandle)
				t.Cleanup(func() {
					if err := h.Close(context.Background()); err != nil {
						t.Error(err)
					}
				})
				if err := h.Start(ctx); err != nil {
					t.Fatal(err)
				}
				h.Activate()
				return h
			}
			h := start()
			listener := net.JoinHostPort(h.endpoint.Host, portString(h.endpoint.Port))
			target := mieruTCPFixture(t)
			dst := access.Endpoint{Host: "127.0.0.1", Port: uint16(target.Addr().(*net.TCPAddr).Port)}
			keys, err := wire.Keys(method, ss.Material(in.Credentials[0].Payload))
			if err != nil {
				t.Fatal(err)
			}
			raw, err := net.Dial("tcp", listener)
			if err != nil {
				t.Fatal(err)
			}
			capture := &ssRequestCapture{Conn: raw}
			c, err := wire.ClientTCP(capture, keys, dst, wire.NewSaltCache(32, time.Minute))
			if err != nil {
				raw.Close()
				t.Fatal(err)
			}
			c.SetDeadline(time.Now().Add(5 * time.Second))
			payload := []byte("authenticated request before generation retirement")
			if _, err = c.Write(payload); err != nil {
				c.Close()
				t.Fatal(err)
			}
			response := make([]byte, len(payload))
			if _, err = io.ReadFull(c, response); err != nil || !bytes.Equal(payload, response) {
				c.Close()
				t.Fatal("initial traffic", err)
			}
			c.Close()
			if err = h.Close(ctx); err != nil {
				t.Fatal(err)
			}
			restarted := start()
			if h.replay != restarted.replay {
				t.Fatal("generation discarded replay ownership")
			}
			replayed, err := net.Dial("tcp", listener)
			if err != nil {
				t.Fatal(err)
			}
			defer replayed.Close()
			replayed.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err = replayed.Write(capture.requests.Bytes()); err != nil {
				t.Fatal(err)
			}
			n, err := replayed.Read(make([]byte, 4096))
			if err == nil || n != 0 {
				t.Fatal("authenticated replay produced a response")
			}
			if e, ok := err.(net.Error); ok && e.Timeout() {
				t.Fatal("replay was not promptly rejected", err)
			}
			if restarted.Stats().Sessions != 0 {
				t.Fatal("replay reached routed target")
			}
			d := shadowsocksClient(t, in, 0)
			defer d.Close()
			if err = shadowsocksTraffic(d, dst, shadowsocksUDPFixture(t)); err != nil {
				t.Fatal("fresh traffic after restart", err)
			}
		})
	}
}

// Sanity measurements include integrity checks, with no machine-specific speed
// threshold. They run over actual owned server/client sockets and routing.
func TestShadowsocksPerformanceSanity(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "2022-blake3-aes-128-gcm"} {
		t.Run(method, func(t *testing.T) {
			ctx := underlay.WithFactory(context.Background(), underlay.New())
			in := shadowsocksIntent(t, method, method != "aes-128-gcm")
			p, err := NewShadowsocksCompiler().Compile(ctx, in)
			if err != nil {
				t.Fatal(err)
			}
			h := p.(*shadowsocksHandle)
			defer h.Close(ctx)
			if err = h.Start(ctx); err != nil {
				t.Fatal(err)
			}
			h.Activate()
			d := shadowsocksClient(t, in, 0)
			defer d.Close()
			target := mieruTCPFixture(t)
			c, err := d.DialContext(ctx, access.Endpoint{Host: "127.0.0.1", Port: uint16(target.Addr().(*net.TCPAddr).Port)})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(15 * time.Second))
			payload := bytes.Repeat([]byte("sanity-TCP-data!"), 262144)
			written := make(chan error, 1)
			begin := time.Now()
			go func() { _, err := c.Write(payload); written <- err }()
			response := make([]byte, len(payload))
			_, err = io.ReadFull(c, response)
			if err != nil {
				c.Close()
			}
			writeErr := <-written
			if err != nil || writeErr != nil || !bytes.Equal(payload, response) {
				t.Fatal("TCP integrity", err, writeErr)
			}
			t.Logf("TCP bytes=%d elapsed=%s echo_MiB_per_second=%.2f", len(payload), time.Since(begin), float64(len(payload))/(1<<20)/time.Since(begin).Seconds())
			udp, err := d.(ports.ClientPacketDialer).ListenPacket(ctx, shadowsocksUDPFixture(t))
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			udp.SetDeadline(time.Now().Add(15 * time.Second))
			packet := bytes.Repeat([]byte("u"), 1200)
			buffer := make([]byte, 4096)
			begin = time.Now()
			for range 128 {
				if _, err = udp.WriteTo(packet, nil); err != nil {
					t.Fatal(err)
				}
				n, _, err := udp.ReadFrom(buffer)
				if err != nil || !bytes.Equal(buffer[:n], packet) {
					t.Fatal("UDP integrity", err)
				}
			}
			t.Logf("UDP packets=128 payload_bytes=1200 elapsed=%s roundtrips_per_second=%.2f", time.Since(begin), 128/time.Since(begin).Seconds())
		})
	}
}

func TestShadowsocksInvalidIntentBeforeActivation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ports.RuntimeIntent)
	}{
		{"unknown method", func(in *ports.RuntimeIntent) {
			in.Inbound.Settings.Data = json.RawMessage(`{"method":"unknown","udp":true}`)
		}},
		{"wrong key size", func(in *ports.RuntimeIntent) {
			in.Credentials[0].Payload = access.PSKPayload{Key: secret.New(base64.StdEncoding.EncodeToString(make([]byte, 15)))}
		}},
		{"bad base64", func(in *ports.RuntimeIntent) {
			in.Credentials[0].Payload = access.PSKPayload{Key: secret.New("synthetic-invalid-encoding")}
		}},
		{"missing key", func(in *ports.RuntimeIntent) { in.Credentials[0].Payload = access.PSKPayload{Key: secret.New("")} }},
		{"missing server identity", func(in *ports.RuntimeIntent) { in.ServerCredentials = nil }},
		{"duplicate identity", func(in *ports.RuntimeIntent) { in.Credentials[1].Payload = in.Credentials[0].Payload }},
		{"broken account binding", func(in *ports.RuntimeIntent) { in.Credentials[0].OwnerAccountID = nil }},
		{"invalid host", func(in *ports.RuntimeIntent) { in.Inbound.Listeners[0].Endpoint.Host = "bad\nhost" }},
		{"invalid port", func(in *ports.RuntimeIntent) { in.Inbound.Listeners[0].Endpoint.Port = 0 }},
		{"invalid UDP listener", func(in *ports.RuntimeIntent) { in.Inbound.Listeners[1].Transport = "tcp" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			in := shadowsocksIntent(t, "2022-blake3-aes-128-gcm", true)
			test.mutate(&in)
			compiler := NewShadowsocksCompiler()
			ctx := underlay.WithFactory(context.Background(), underlay.New())
			prepared, err := compiler.Compile(ctx, in)
			if err == nil {
				prepared.Close(ctx)
				t.Fatal("invalid configuration reached runtime preparation")
			}
			if len(compiler.states) != 0 {
				t.Fatal("invalid configuration reserved replay state")
			}
		})
	}
}
