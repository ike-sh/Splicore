package native

import (
	"context"
	"errors"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientio"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks5"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"io"
	"net"
	"testing"
	"time"
)

func TestPhase20ProxyBlockedWriteLiveDeadlineAndParentClose(t *testing.T) {
	for _, packet := range []bool{false, true} {
		local, peer := net.Pipe()
		defer peer.Close()
		owner := clientio.New()
		var write func() error
		var closeChild func()
		if packet {
			control, remoteControl := net.Pipe()
			defer remoteControl.Close()
			p := &socksPacket{control: control, udp: local, done: make(chan struct{}), registered: make(chan struct{})}
			go p.watch()
			release, e := owner.Track(p)
			if e != nil {
				t.Fatal(e)
			}
			p.release = release
			close(p.registered)
			write = func() error {
				_, e := p.WriteTo([]byte("packet"), netaddr.UDP(access.Endpoint{Host: "127.0.0.1", Port: 53}))
				return e
			}
			closeChild = func() { _ = p.Close() }
		} else {
			c, e := owner.Conn(local)
			if e != nil {
				t.Fatal(e)
			}
			write = func() error { _, e := c.Write([]byte("stream")); return e }
			closeChild = func() { _ = c.Close() }
		}
		blocked := make(chan error, 1)
		go func() { blocked <- write() }()
		if e := local.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); e != nil {
			t.Fatal(e)
		}
		select {
		case e := <-blocked:
			var timeout net.Error
			if !errors.As(e, &timeout) || !timeout.Timeout() {
				t.Fatal("live blocked-write deadline", e)
			}
		case <-time.After(time.Second):
			t.Fatal("deadline did not wake writer")
		}
		_ = local.SetWriteDeadline(time.Time{})
		go func() { blocked <- write() }()
		closed := make(chan struct{})
		go func() { owner.Close(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("parent close did not join")
		}
		if <-blocked == nil {
			t.Fatal("blocked write survived Close")
		}
		closeChild()
	}
}
func TestPhase20ProxyHalfClose(t *testing.T) {
	port, _, _ := independentSOCKSPeer(t, false)
	n, c := proxyNode(t, "socks5", port, false)
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	d, e := (SOCKS5OutboundFactory{}).Build(ctx, n, c)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	conn, e := d.DialContext(ctx, access.Endpoint{Host: "remote.invalid", Port: 80})
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if e = socks5.WriteFull(conn, []byte("half-close")); e != nil {
		t.Fatal(e)
	}
	if e = conn.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(conn)
	if e != nil || string(b) != "half-close" {
		t.Fatal("half-close response", e)
	}
}
