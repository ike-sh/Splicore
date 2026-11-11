package xhttp

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
)

func FuzzPhase33MetadataSequence(f *testing.F) {
	f.Add("/x/550e8400-e29b-41d4-a716-446655440000/0", "0", uint8(0))
	f.Add("/x/?x=1&x=2", "18446744073709551616", uint8(3))
	f.Fuzz(func(t *testing.T, path, sequence string, placement uint8) {
		if len(path)+len(sequence) > 8192 {
			return
		}
		places := []string{"path", "query", "header", "cookie"}
		c := cfg.Config{Kind: "xhttp", Path: "/x", XHTTP: &cfg.XHTTP{SessionPlacement: places[placement%4], SequencePlacement: places[(placement/4)%4]}}
		u, err := url.ParseRequestURI(path)
		if err != nil {
			return
		}
		r := &http.Request{Method: "POST", URL: u, Header: make(http.Header), Host: "fixture.test"}
		putValue(r, places[(placement/4)%4], options(c).SequenceKey, sequence)
		_, _, _ = parseEnvelope(r, c)
	})
}

func FuzzPhase33ReassemblyBounds(f *testing.F) {
	f.Add([]byte{2, 0, 1, 1, 255}, uint64(0))
	f.Add([]byte{255, 254, 253}, ^uint64(0))
	f.Fuzz(func(t *testing.T, b []byte, base uint64) {
		if len(b) > 256 {
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		l := &Listener{config: cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{Buffered: 8}}}
		s := &session{owner: l, ctx: ctx, packets: map[uint64][]byte{}, notify: make(chan struct{}, 1), next: base}
		for _, v := range b {
			_ = s.enqueue(base+uint64(v), []byte{v})
		}
		if len(s.packets) > 8 || s.bytes > 8 || l.pending > 8 {
			t.Fatal("unbounded reorder state")
		}
	})
}
