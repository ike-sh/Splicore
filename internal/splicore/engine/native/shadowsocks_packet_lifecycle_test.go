package native

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/packetio"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/shadowsocks/wire"
)

func TestShadowsocksSharedReplyChildClose(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "2022-blake3-aes-128-gcm"} {
		t.Run(method, func(t *testing.T) {
			password := "synthetic-password"
			if method != "aes-128-gcm" {
				password = "AAAAAAAAAAAAAAAAAAAAAA=="
			}
			keys, err := wire.Keys(method, password)
			if err != nil {
				t.Fatal(err)
			}
			parent, cancel := context.WithCancel(context.Background())
			entered, release := make(chan []byte, 2), make(chan struct{})
			w := packetio.NewAddressWriter(parent, func(b []byte, _ net.Addr) error {
				entered <- b
				select {
				case <-release:
					return nil
				case <-parent.Done():
					return net.ErrClosed
				}
			})
			defer w.Wait()
			defer cancel()
			h := &shadowsocksHandle{ctx: parent, packetWriter: w, sessions: map[shadowsocksAssociationID]*shadowsocksServerPacket{}, replay: &shadowsocksReplayState{salts: wire.NewSaltCache(64, time.Minute)}}
			makeChild := func(id uint64) *shadowsocksServerPacket {
				ctx, closeChild := context.WithCancel(parent)
				return &shadowsocksServerPacket{h: h, key: keys[0], session: id, source: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}, done: make(chan struct{}), ctx: ctx, cancel: closeChild}
			}
			a, b := makeChild(1), makeChild(2)
			defer a.Close()
			defer b.Close()
			result := make(chan error, 1)
			dst := access.Endpoint{Host: "127.0.0.1", Port: 12345}
			go func() { result <- a.writePayload([]byte("blocked"), dst) }()
			<-entered
			a.Close()
			select {
			case err := <-result:
				if !errors.Is(err, net.ErrClosed) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("shared reply survived child Close")
			}
			close(release)
			if err := b.writePayload([]byte("sibling"), dst); err != nil {
				t.Fatal(err)
			}
		})
	}
}
