package relay

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
)

// Packets owns each numeric target socket and joins every reply worker before
// returning its borrowed protocol packet. Each worker has private scratch.
func Packets(ctx context.Context, packet net.PacketConn, dial func(context.Context, access.Endpoint) (net.Conn, error), idle time.Duration) error {
	targets := map[access.Endpoint]net.Conn{}
	var readers sync.WaitGroup
	stop := context.AfterFunc(ctx, func() { _ = packet.Close() })
	defer stop()
	defer func() {
		_ = packet.Close()
		for _, c := range targets {
			_ = c.Close()
		}
		readers.Wait()
	}()
	buffer := make([]byte, 65535)
	for {
		if idle > 0 {
			_ = packet.SetReadDeadline(time.Now().Add(idle))
		}
		n, a, err := packet.ReadFrom(buffer)
		if err != nil {
			return err
		}
		dst, err := netaddr.From(a)
		if err != nil {
			return err
		}
		target := targets[dst]
		if target == nil {
			if len(targets) >= 128 {
				return net.InvalidAddrError("too many UDP targets")
			}
			target, err = dial(ctx, dst)
			if err != nil {
				return err
			}
			targets[dst] = target
			readers.Add(1)
			go func(c net.Conn) {
				defer readers.Done()
				scratch := make([]byte, 65535)
				for {
					n, err := c.Read(scratch)
					if err != nil {
						return
					}
					if idle > 0 {
						_ = packet.SetReadDeadline(time.Now().Add(idle))
					}
					if _, err = packet.WriteTo(scratch[:n], c.RemoteAddr()); err != nil {
						_ = packet.Close()
						return
					}
				}
			}(target)
		}
		if nwrite, err := target.Write(buffer[:n]); err != nil {
			return err
		} else if nwrite != n {
			return io.ErrShortWrite
		}
	}
}
