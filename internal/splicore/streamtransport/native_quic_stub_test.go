//go:build !with_quic

package streamtransport

import (
	"testing"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
)

func TestPhase31MissingQUICBuildFailsClosed(t *testing.T) {
	server, client := nativeTLSFixture(t)
	c := cfg.Config{Kind: "quic-stream"}
	if _, e := NewPacketClient(nil, c, client); e == nil {
		t.Fatal("missing QUIC accepted")
	}
	base, e := ListenCarrier(t.Context(), "127.0.0.1:0", c)
	if e != nil {
		t.Fatal(e)
	}
	defer base.Close()
	if _, e = WrapListener(base, c, server); e == nil {
		t.Fatal("missing QUIC listener accepted")
	}
}
