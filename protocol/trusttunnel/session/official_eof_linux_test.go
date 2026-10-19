//go:build linux && with_quic

package session

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/ike-sh/Splicore/protocol/trusttunnel/wire"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOfficialH3EOFAdapterComparison(t *testing.T) {
	root := oracleRoot(t)
	dir, h2, h3, tc := startOfficialEndpoint(t, root, false)
	if os.Getenv("SPLICORE_TRUSTTUNNEL_QLOG") == "1" {
		t.Setenv("QLOGDIR", filepath.Join(dir, "qlog"))
	}
	c := newClient(t, "auto", h3, tc, func(cfg *ClientConfig) {
		cfg.Addresses = []string{h3, h2}
		cfg.FallbackDelay = 5 * time.Millisecond
		cfg.ConnectTimeout = time.Second
	})
	target := tcpEcho(t, "tcp4", "192.0.2.29:0")
	rows := []map[string]any{}
	failures := 0
	for i := range 20 {
		if e := c.Check(context.Background()); e != nil {
			t.Fatal(e)
		}
		c.mu.Lock()
		owner := c.session
		c.mu.Unlock()
		if owner.mode != "http3" {
			t.Fatal("diagnostic requires H3")
		}
		for _, lane := range []string{"body-adapter", "raw-request-stream"} {
			var e error
			streamID := int64(-1)
			if lane == "body-adapter" {
				e = transfer(c, target, 16384)
			} else {
				raw := owner.raw.(*h3Connection)
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				stream, err := raw.client.OpenRequestStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				streamID = int64(stream.StreamID())
				stream.SetDeadline(time.Now().Add(15 * time.Second))
				e = stream.SendRequestHeader(&http.Request{Method: "CONNECT", URL: &url.URL{Scheme: "https", Host: target}, Host: target, Header: c.headers(target), ContentLength: -1})
				if e == nil {
					var response *http.Response
					response, e = stream.ReadResponse()
					if e == nil && response.StatusCode != 200 {
						e = status(response.StatusCode)
					}
				}
				if e == nil {
					payload := bytes.Repeat([]byte("TrustTunnel native integrity\x00"), 1+16384/29)[:16384]
					_, e = stream.Write(payload)
					if e == nil {
						e = stream.Close()
					}
					if e == nil {
						var got []byte
						got, e = io.ReadAll(stream)
						if e == nil && !bytes.Equal(got, payload) {
							e = io.ErrUnexpectedEOF
						}
					}
				}
				stream.CancelRead(0x10c)
				stream.CancelWrite(0x10c)
				cancel()
			}
			rows = append(rows, map[string]any{"iteration": i, "lane": lane, "stream_id": streamID, "error": errorText(e), "PASS": e == nil})
			if e != nil {
				failures++
				t.Logf("iteration=%d lane=%s error=%v", i, lane, e)
			}
		}
	}
	b, _ := json.MarshalIndent(rows, "", "  ")
	oracleWrite(t, dir, "EOF-comparison.json", string(b))
	if failures != 0 {
		t.Fatalf("EOF comparison failures=%d", failures)
	}
}

// This lane deliberately uses only the generic HTTP/3 library, without the
// TrustTunnel session manager, health monitor, stream adapter or selection race.
// It shares the target fixture, credentials, payload and 15s EOF deadline.
func TestOfficialH3EOFGenericComparison(t *testing.T) {
	root := oracleRoot(t)
	dir, _, address, tc := startOfficialEndpoint(t, root, false)
	target := tcpEcho(t, "tcp4", "192.0.2.29:0")
	if os.Getenv("SPLICORE_TRUSTTUNNEL_QLOG") == "1" {
		t.Setenv("QLOGDIR", filepath.Join(dir, "qlog"))
	}
	packet, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer packet.Close()
	remote, e := net.ResolveUDPAddr("udp4", address)
	if e != nil {
		t.Fatal(e)
	}
	tr := &quic.Transport{Conn: packet}
	defer tr.Close()
	tc.NextProtos = []string{"h3"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	q, e := tr.Dial(ctx, remote, tc, &quic.Config{Tracer: qlog.DefaultConnectionTracer, Versions: []quic.Version{quic.Version1}, HandshakeIdleTimeout: time.Second, MaxIdleTimeout: 16 * time.Second, InitialStreamReceiveWindow: 131072, MaxStreamReceiveWindow: 1 << 20, InitialConnectionReceiveWindow: 8 << 20, MaxConnectionReceiveWindow: 16 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer q.CloseWithError(0, "")
	client := (&http3.Transport{DisableCompression: true}).NewClientConn(q)
	open := func(authority string) *http3.RequestStream {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		s, e := client.OpenRequestStream(ctx)
		if e != nil {
			t.Fatal(e)
		}
		s.SetDeadline(time.Now().Add(15 * time.Second))
		e = s.SendRequestHeader(&http.Request{Method: "CONNECT", URL: &url.URL{Scheme: "https", Host: authority}, Host: authority, Header: http.Header{"User-Agent": {"Splicore direct generic diagnostic"}, "Proxy-Authorization": {wire.Authorization("alpha", "alpha-pass")}}, ContentLength: -1})
		if e != nil {
			t.Fatal(e)
		}
		r, e := s.ReadResponse()
		if e != nil || r.StatusCode != 200 {
			t.Fatal(e)
		}
		return s
	}
	rows := []map[string]any{}
	failures := 0
	for i := range 100 {
		h := open("_check")
		h.Close()
		h.CancelRead(0x10c)
		s := open(target)
		payload := bytes.Repeat([]byte("TrustTunnel native integrity\x00"), 1+16384/29)[:16384]
		_, we := s.Write(payload)
		ce := s.Close()
		got, re := io.ReadAll(s)
		ok := we == nil && ce == nil && re == nil && bytes.Equal(got, payload)
		rows = append(rows, map[string]any{"iteration": i, "stream_id": s.StreamID(), "received": len(got), "expected": len(payload), "integrity": bytes.Equal(got, payload), "read_error": errorText(re), "write_error": errorText(we), "close_error": errorText(ce), "PASS": ok})
		s.CancelRead(0x10c)
		s.CancelWrite(0x10c)
		if !ok {
			failures++
			t.Logf("generic iteration=%d stream=%d bytes=%d error=%v", i, s.StreamID(), len(got), re)
		}
	}
	b, _ := json.MarshalIndent(rows, "", "  ")
	oracleWrite(t, dir, "generic-EOF-comparison.json", string(b))
	if failures != 0 {
		t.Fatalf("generic EOF failures=%d", failures)
	}
}
