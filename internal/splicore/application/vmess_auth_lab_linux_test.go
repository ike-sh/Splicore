//go:build linux && with_gvisor && with_quic && with_utls && splicore_tun_lab

package application_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/vmess"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/vmess/wire"
	"io"
	"net"
	"testing"
	"time"
)

type phase19AuthNode struct {
	node       client.RemoteNode
	credential access.Credential
}
type phase19AuthMetrics struct{ Accepted, DuplicateRejected, InvalidClockRejected, InvalidAuthRejected, BadTagRejected, Unexpected int }

func phase19AuthTraffic(t *testing.T, node phase19AuthNode, target access.Endpoint, metrics *phase19AuthMetrics) {
	t.Helper()
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	d, err := underlay.DialerFrom(ctx, underlay.ProxyUnderlay)
	if err != nil {
		t.Fatal(err)
	}
	key := module.CommandKey(node.credential.Payload.(access.UUIDPayload))
	opts, _ := module.DecodeClientOptions(node.node.Options.Data)
	security, _ := module.Security(opts.Security)
	options := byte(wire.ChunkStream | wire.LengthMask)
	if security == wire.None {
		options = 0
	}
	r, err := wire.NewRequest(target, wire.TCP, security, options, nil)
	if err != nil {
		t.Fatal(err)
	}
	header, err := wire.EncodeRequest(key, r, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	open := func() net.Conn {
		c, err := d.DialContext(ctx, "tcp", netaddr.TCP(node.node.Endpoint).String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if node.node.Security.Kind == "tls" {
			config, err := clientconfig.TLS(node.node.Security.TLS, node.node.Endpoint.Host)
			if err != nil {
				t.Fatal(err)
			}
			tc := tls.Client(c, config)
			if err = tc.HandshakeContext(ctx); err != nil {
				_ = c.Close()
				t.Fatal(err)
			}
			c = tc
		}
		return c
	}
	c := open()
	if _, err = c.Write(header); err != nil {
		_ = c.Close()
		t.Fatal(err)
	}
	payload := []byte("Phase19 synthetic authentication acceptance")
	var frame []byte
	tx, _ := wire.NewChunk(r, false, nil)
	if options == 0 {
		frame = payload
	} else {
		frame, err = tx.Encode(payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err = c.Write(frame); err != nil {
		_ = c.Close()
		t.Fatal(err)
	}
	if err = wire.ReadResponse(c, r); err != nil {
		_ = c.Close()
		t.Fatal("accepted response", err)
	}
	if options == 0 {
		b := make([]byte, len(payload))
		n, err := io.ReadFull(c, b)
		if err != nil || !bytes.Equal(b[:n], payload) {
			_ = c.Close()
			t.Fatal("accepted raw payload", err)
		}
	} else {
		rx, _ := wire.NewChunk(r, true, nil)
		b, err := rx.Read(c)
		if err != nil || !bytes.Equal(b, payload) {
			_ = c.Close()
			t.Fatal("accepted payload", err)
		}
	}
	_ = c.Close()
	metrics.Accepted++
	clock, _ := wire.EncodeRequest(key, r, time.Now().Add(-121*time.Second), nil)
	badAuth := bytes.Clone(header)
	badAuth[0] ^= 1
	badTag := bytes.Clone(header)
	badTag[len(badTag)-1] ^= 1
	for index, b := range [][]byte{header, clock, badAuth, badTag} {
		c := open()
		if _, err = c.Write(b); err != nil {
			_ = c.Close()
			t.Fatal("auth probe delivery", err)
		}
		err = wire.ReadResponse(c, r)
		_ = c.Close()
		if err == nil {
			metrics.Unexpected++
			t.Fatal("unexpected invalid/replayed authentication accepted")
		}
		switch index {
		case 0:
			metrics.DuplicateRejected++
		case 1:
			metrics.InvalidClockRejected++
		case 2:
			metrics.InvalidAuthRejected++
		case 3:
			metrics.BadTagRejected++
		}
	}
}
