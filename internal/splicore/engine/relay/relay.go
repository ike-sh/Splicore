// Package relay joins the two directions of one owned plaintext stream.
package relay

import (
	"context"
	"io"
	"net"
)

// Join owns both connections until both copy workers have completed. Each copy
// owns its io.Copy buffer. Shutdown closes sockets to interrupt blocked reads;
// an ordinary upload EOF preserves the destination's response via half-close.
func Join(ctx context.Context, client, target net.Conn) {
	closeBoth := func() { _ = client.Close(); _ = target.Close() }
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	defer closeBoth()
	done := make(chan error, 2)
	copyTo := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if err == nil {
			if h, ok := dst.(interface{ CloseWrite() error }); ok {
				err = h.CloseWrite()
			} else {
				_ = dst.Close()
			}
		}
		done <- err
	}
	go copyTo(target, client)
	go copyTo(client, target)
	if err := <-done; err != nil {
		closeBoth()
	}
	<-done
}
