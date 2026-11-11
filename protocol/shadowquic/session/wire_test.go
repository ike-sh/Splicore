package session

import (
	"bytes"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

func TestWireRoundTripAndRejection(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "target.test"} {
		dst := access.Endpoint{Host: host, Port: 443}
		for _, cmd := range []byte{connect, associate, associateStream} {
			b, e := command(cmd, dst)
			if e != nil {
				t.Fatal(e)
			}
			c, d, e := readCommand(bytes.NewReader(b))
			if e != nil || c != cmd || d != dst {
				t.Fatal(c, d, e)
			}
			for n := range len(b) {
				if _, _, e = readCommand(bytes.NewReader(b[:n])); e == nil {
					t.Fatal("truncated command", n)
				}
			}
		}
		b, e := mapping(dst, 65535)
		if e != nil {
			t.Fatal(e)
		}
		d, id, e := readMapping(bytes.NewReader(b))
		if e != nil || d != dst || id != 65535 {
			t.Fatal(d, id, e)
		}
		for n := range len(b) {
			if _, _, e = readMapping(bytes.NewReader(b[:n])); e == nil {
				t.Fatal("truncated mapping", n)
			}
		}
	}
	for _, b := range [][]byte{{2, 1, 127, 0, 0, 1, 0, 80}, {5}, {255}, {1, 9}, {1, 3, 0, 0, 80}, {1, 3, 1, 0, 0, 80}, {1, 1, 127, 0, 0, 1, 0, 0}} {
		if _, _, e := readCommand(bytes.NewReader(b)); e == nil {
			t.Fatal("bad command accepted", b)
		}
	}
	if _, _, e := readCommand(bytes.NewReader([]byte{3, 1, 0, 0, 0, 0, 0, 0})); e != nil {
		t.Fatal("wildcard binding", e)
	}
}

func TestLimits(t *testing.T) {
	if (Limits{}).Validate() != nil {
		t.Fatal("defaults")
	}
	for _, l := range []Limits{{MaxConnections: 129}, {MaxStreams: 257}, {MaxFlows: 129}, {HandshakeSeconds: 31}, {IdleSeconds: 9}, {KeepAliveSeconds: 60}, {UDPIdleSeconds: 1}, {MaxStreams: -1}} {
		if l.Validate() == nil {
			t.Fatal(l)
		}
	}
}

func FuzzCommand(f *testing.F) {
	f.Add([]byte{1, 1, 127, 0, 0, 1, 0, 80})
	f.Add([]byte{3, 1, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{4})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1024 {
			return
		}
		cmd, d, e := readCommand(bytes.NewReader(b))
		if e == nil {
			raw, e := command(cmd, d)
			if e != nil || len(raw) > 260 {
				t.Fatal("unbounded command")
			}
		}
	})
}

func FuzzMapping(f *testing.F) {
	f.Add([]byte{1, 127, 0, 0, 1, 0, 80, 0, 1})
	f.Add([]byte{3, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1024 {
			return
		}
		d, id, e := readMapping(bytes.NewReader(b))
		if e == nil {
			raw, e := mapping(d, id)
			if e != nil || len(raw) > 261 {
				t.Fatal("unbounded mapping")
			}
		}
	})
}
