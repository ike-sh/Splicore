//go:build with_quic

package xhttp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// Capture both physical objects before the server can reject a request and
// retire its client carrier. Endpoint metadata is diagnostic, never a key.
type h3RetryPeer struct {
	*quic.Conn
	transport *h3Transport
	socket    *h3Socket
	endpoint  net.Addr
	closePeer func() error
}

func h3RetryConnectionKey(q *quic.Conn) ([]byte, error) {
	state := q.ConnectionState().TLS
	return state.ExportKeyingMaterial("EXPORTER-Splicore-test-connection", nil, 32)
}

// TLS exporters bind the two ends of one handshake without using either UDP
// endpoint or dial completion order. Only the captured socket pointer is used
// afterward, including after removal from the transport registry.
func h3RetryCapture(cl *Client, peer *quic.Conn) (*h3RetryPeer, error) {
	key, err := h3RetryConnectionKey(peer)
	if err != nil {
		return nil, err
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		cl.pool.mu.Lock()
		var target *h3RetryPeer
		for _, entry := range cl.pool.entries {
			h := entry.transport.(*h3Transport)
			h.mu.Lock()
			for socket := range h.sockets {
				if socket.conn == nil {
					continue
				}
				candidate, err := h3RetryConnectionKey(socket.conn)
				if err == nil && bytes.Equal(candidate, key) {
					target = &h3RetryPeer{Conn: peer, transport: h, socket: socket, endpoint: peer.RemoteAddr(), closePeer: func() error {
						return peer.CloseWithError(0x1ab, "retry ownership regression")
					}}
					break
				}
			}
			h.mu.Unlock()
			if target != nil {
				break
			}
		}
		cl.pool.mu.Unlock()
		if target != nil {
			return target, nil
		}
		select {
		case <-peer.Context().Done():
			return nil, context.Cause(peer.Context())
		case <-timer.C:
			return nil, fmt.Errorf("server QUIC object %p has no captured client socket", peer)
		case <-tick.C:
		}
	}
}

func h3RetryCloseError(ctx context.Context, target *h3RetryPeer) error {
	if target == nil || target.socket == nil || target.socket.conn == nil || target.closePeer == nil {
		return fmt.Errorf("missing captured physical retry target")
	}
	if err := target.closePeer(); err != nil {
		return err
	}
	select {
	case <-target.socket.conn.Context().Done():
		return nil
	case <-ctx.Done():
		return fmt.Errorf("captured client QUIC object %p did not terminate: %w", target.socket.conn, ctx.Err())
	}
}

func TestXHTTPH3RetrySocketIdentityCollision(t *testing.T) {
	cl, front := h3RetryFixture(t, "packet-up", nil)
	front.reject.Store(false)
	aConn, aSession := h3DialSession(t, cl)
	a := front.connection(t)
	aConn.Close()
	h3AwaitTerminal(t, aSession)
	front.reject.Store(true)
	bConn, bSession := h3DialSession(t, cl)
	b := front.connection(t)
	h := bSession.download.transport.(*h3Transport)
	h3RetryDistinct(t, a, b)
	h3ReclaimRetiredSocket(t, h, a.socket)

	// A deterministic metadata collision models legitimate kernel endpoint
	// reuse without ever releasing and reacquiring a particular UDP port.
	b.endpoint = a.endpoint
	var oldSelection *h3RetryPeer
	for _, current := range []*h3RetryPeer{b} {
		if current.endpoint.String() == a.endpoint.String() {
			oldSelection = current
		}
	}
	if oldSelection != b || h3RetrySocket(t, h, a) != a.socket {
		t.Fatal("address failure control or exact historical socket selection failed")
	}
	h3RetryClose(t, h, a)
	if b.socket.conn.Context().Err() != nil || b.Context().Err() != nil {
		t.Fatal("old target cleanup terminated healthy B")
	}
	exchange(t, bConn, []byte("B data after exact historical A termination"))
	bConn.Close()
	h3AwaitTerminal(t, bSession)
	h3ReclaimBound(t, h, 1, 1, 0)
	cl.Close()
	h3ReclaimBound(t, h, 0, 0, 0)
	h3ReclaimRetiredSocket(t, h, b.socket)
	t.Logf("same_endpoint_metadata=true old_algorithm_selected_B=true exact_target_A=true A_retired=true B_post_A_traffic=PASS A_socket=%p B_socket=%p", a.socket, b.socket)
}

func TestXHTTPH3RetrySocketIdentityNegativeControl(t *testing.T) {
	cl, front := h3RetryFixture(t, "packet-up", nil)
	front.reject.Store(false)
	aConn, aSession := h3DialSession(t, cl)
	a := front.connection(t)
	front.reject.Store(true)
	bConn, bSession := h3DialSession(t, cl)
	b := front.connection(t)
	h := bSession.download.transport.(*h3Transport)
	b.endpoint = a.endpoint
	// Keep the real A connection alive despite a successful close operation.
	// The production-facing helper uses this same error-returning wait path.
	retained := *a
	retained.closePeer = func() error { return nil }
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := h3RetryCloseError(ctx, &retained); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("oracle missed intentionally unterminated A", err)
	}
	exchange(t, aConn, []byte("negative control A still alive"))
	exchange(t, bConn, []byte("negative control B also alive"))
	h3RetryClose(t, h, a)
	h3AwaitTerminal(t, aSession)
	exchange(t, bConn, []byte("B survives observed A termination"))
	bConn.Close()
	h3AwaitTerminal(t, bSession)
	cl.Close()
	h3ReclaimBound(t, h, 0, 0, 0)
	h3ReclaimRetiredSocket(t, h, a.socket)
	h3ReclaimRetiredSocket(t, h, b.socket)
	t.Log("negative_control=unterminated_exact_A detected=true A_termination=PASS B_post_A_traffic=PASS")
}
