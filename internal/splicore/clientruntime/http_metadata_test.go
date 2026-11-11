package clientruntime

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"net/textproto"
	"strings"
	"testing"

	httpproxy "github.com/ike-sh/Splicore/internal/splicore/protocol/http"
)

func TestPhase20HTTPTrailerOwnership(t *testing.T) {
	raw := "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nConnection: X-Hop\r\nProxy-Authorization: header-secret\r\nTransfer-Encoding: chunked\r\nTrailer: X-Safe, Proxy-Authorization, X-Hop\r\n\r\n3\r\nabc\r\n0\r\nX-Safe: exact\r\nX-Safe: second\r\nProxy-Authorization: trailer-secret\r\nX-Hop: hop-secret\r\nX-Undeclared: ignored\r\n\r\n"
	in, _, err := httpproxy.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	out := forwardHTTPRequest(in)
	if in.Header.Get("Proxy-Authorization") == "" || in.Trailer.Get("X-Safe") != "" || len(out.Trailer) != 1 {
		t.Fatal("metadata ownership/declarations")
	}
	if out.Header.Get("Proxy-Authorization") != "" {
		t.Fatal("ordinary credential")
	}
	b, err := io.ReadAll(out.Body)
	if err != nil || string(b) != "abc" {
		t.Fatal("body", err)
	}
	if in.Trailer.Get("Proxy-Authorization") == "" || len(out.Trailer) != 1 || strings.Join(out.Trailer.Values("X-Safe"), ",") != "exact,second" {
		t.Fatal("late trailer policy")
	}
	in.Trailer["X-Safe"][0] = "mutated"
	if out.Trailer.Get("X-Safe") != "exact" {
		t.Fatal("value slice aliased")
	}
	out.Header.Set("X-Owned", "out")
	if in.Header.Get("X-Owned") != "" {
		t.Fatal("header aliased")
	}
	if err := out.Body.Close(); err != nil {
		t.Fatal(err)
	}
}

type terminalMetadataBody struct {
	err    error
	closed bool
}

func TestPhase20HTTPTrailerFramingDeclarationsRejected(t *testing.T) {
	for _, name := range []string{"Transfer-Encoding", "Trailer", "Content-Length"} {
		raw := "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nTransfer-Encoding: chunked\r\nTrailer: " + name + "\r\n\r\n0\r\n\r\n"
		if _, _, err := httpproxy.ReadRequest(bufio.NewReader(strings.NewReader(raw))); err == nil {
			t.Fatalf("forbidden framing declaration accepted: %s", name)
		}
	}
}

func (b *terminalMetadataBody) Read(p []byte) (int, error) { return copy(p, "last"), b.err }
func (b *terminalMetadataBody) Close() error               { b.closed = true; return io.ErrClosedPipe }

func TestPhase20HTTPTrailerTerminalReadAndClose(t *testing.T) {
	for _, terminal := range []error{io.EOF, io.ErrUnexpectedEOF, errors.New("malformed final chunk")} {
		in := http.Header{"X-Safe": {"exact"}, "Proxy-Authorization": {"synthetic-secret"}}
		out := forwardHTTPTrailers(nil, in)
		inner := &terminalMetadataBody{err: terminal}
		body := forwardHTTPBody(inner, in, out)
		p := make([]byte, 8)
		n, err := body.Read(p)
		if n != 4 || string(p[:n]) != "last" || err != terminal {
			t.Fatal("read semantics")
		}
		if (out.Get("X-Safe") == "exact") != (terminal == io.EOF) {
			t.Fatal("publication outside EOF")
		}
		if err = body.Close(); err != io.ErrClosedPipe || !inner.closed {
			t.Fatal("Close propagation")
		}
		if _, ok := out["Proxy-Authorization"]; ok {
			t.Fatal("forbidden key")
		}
	}
}

func FuzzHTTPForwardTrailers(f *testing.F) {
	for _, name := range []string{"Proxy-Authorization", "pRoXy-AuThOrIzAtIoN", "X-Safe", "Connection", "Transfer-Encoding", "", "X-Safe, Proxy-Authorization", "bad\r\nname", strings.Repeat("x", 8193)} {
		f.Add(name, "value", "X-Hop, Proxy-Authorization")
	}
	f.Fuzz(func(t *testing.T, name, value, connection string) {
		if len(name) > 65536 || len(value) > 65536 || len(connection) > 65536 {
			t.Skip()
		}
		in := http.Header{name: {value}, "X-Safe": {"safe"}, "Proxy-Authorization": {"synthetic"}, "X-Hop": {"hop"}}
		out := forwardHTTPTrailers(http.Header{"Connection": {connection, "X-Hop"}}, in)
		for k := range out {
			if !validTrailerName(k) || k != textproto.CanonicalMIMEHeaderKey(k) {
				t.Fatal("invalid declaration")
			}
			for _, forbidden := range []string{"Proxy-Authorization", "Proxy-Authenticate", "Proxy-Authentication-Info", "Connection", "Proxy-Connection", "Keep-Alive", "Transfer-Encoding", "Content-Length", "Host", "Trailer", "TE", "Upgrade", "X-Hop"} {
				if strings.EqualFold(k, forbidden) {
					t.Fatal("forbidden declaration")
				}
			}
			for _, token := range strings.Split(connection, ",") {
				if strings.EqualFold(k, strings.TrimSpace(token)) {
					t.Fatal("nominated declaration")
				}
			}
		}
	})
}
