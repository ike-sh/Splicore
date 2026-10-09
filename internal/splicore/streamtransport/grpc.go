package streamtransport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protowire"
)

// The researched Tun contract is a protobuf message with byte field 1. This
// independently written codec uses protobuf's bounded wire primitives; grpc-go
// owns gRPC envelopes, HTTP/2, flow control, status and cancellation.
type hunk struct{ data []byte }
type hunkCodec struct{}

func (hunkCodec) Name() string { return "proto" }
func (hunkCodec) Marshal(v any) ([]byte, error) {
	m, ok := v.(*hunk)
	if !ok || len(m.data) > MaxMessage {
		return nil, errors.New("invalid transport message")
	}
	b := protowire.AppendTag(nil, 1, protowire.BytesType)
	return protowire.AppendBytes(b, m.data), nil
}
func (hunkCodec) Unmarshal(b []byte, v any) error {
	m, ok := v.(*hunk)
	if !ok || len(b) > MaxMessage+16 {
		return errors.New("invalid transport message")
	}
	m.data = nil
	fields := 0
	for len(b) > 0 {
		fields++
		if fields > 32 {
			return errors.New("too many transport fields")
		}
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return errors.New("invalid transport protobuf")
		}
		b = b[n:]
		if num == 1 {
			if typ != protowire.BytesType {
				return errors.New("invalid transport field")
			}
			data, n := protowire.ConsumeBytes(b)
			if n < 0 || len(data) > MaxMessage {
				return errors.New("invalid transport payload")
			}
			m.data = append(m.data[:0], data...)
			b = b[n:]
		} else {
			n = protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return errors.New("invalid transport protobuf")
			}
			b = b[n:]
		}
	}
	return nil
}

type rpcStream interface {
	SendMsg(any) error
	RecvMsg(any) error
}
type recvResult struct {
	b []byte
	e error
}
type sendRequest struct {
	b      []byte
	result chan error
}
type grpcConn struct {
	ctx           context.Context
	cancel        context.CancelFunc
	stream        rpcStream
	connection    *grpc.ClientConn
	local, remote net.Addr
	once          sync.Once
	rg, wg        chan struct{}
	rd, wd        deadline
	rx            chan recvResult
	tx            chan sendRequest
	pending       []byte
	readErr       error
	workers       sync.WaitGroup
	joined        chan struct{}
}

func newGRPC(parent context.Context, s rpcStream, cancel context.CancelFunc, connection *grpc.ClientConn, local, remote net.Addr) *grpcConn {
	ctx, stop := context.WithCancel(parent)
	c := &grpcConn{ctx: ctx, cancel: func() {
		stop()
		if cancel != nil {
			cancel()
		}
	}, stream: s, connection: connection, local: local, remote: remote, rg: make(chan struct{}, 1), wg: make(chan struct{}, 1), rx: make(chan recvResult, 1), tx: make(chan sendRequest), joined: make(chan struct{})}
	c.rg <- struct{}{}
	c.wg <- struct{}{}
	c.workers.Add(2)
	go func() {
		defer c.workers.Done()
		for {
			var m hunk
			e := s.RecvMsg(&m)
			select {
			case c.rx <- recvResult{m.data, e}:
			case <-ctx.Done():
				return
			}
			if e != nil {
				return
			}
		}
	}()
	go func() {
		defer c.workers.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case r := <-c.tx:
				e := s.SendMsg(&hunk{r.b})
				r.result <- e
				if e != nil {
					return
				}
			}
		}
	}()
	go func() { c.workers.Wait(); close(c.joined) }()
	return c
}
func (c *grpcConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if e := acquire(c.ctx, c.rg, &c.rd); e != nil {
		return 0, e
	}
	defer func() { c.rg <- struct{}{} }()
	for {
		if c.ctx.Err() != nil {
			return 0, net.ErrClosed
		}
		if len(c.pending) > 0 {
			n := copy(p, c.pending)
			c.pending = c.pending[n:]
			return n, nil
		}
		if c.readErr != nil {
			return 0, c.readErr
		}
		t, changed := c.rd.snapshot()
		if !t.IsZero() && !time.Now().Before(t) {
			return 0, os.ErrDeadlineExceeded
		}
		tm, expired := timer(t)
		select {
		case <-c.ctx.Done():
			if tm != nil {
				tm.Stop()
			}
			return 0, net.ErrClosed
		case <-changed:
			if tm != nil {
				tm.Stop()
			}
			continue
		case <-expired:
			return 0, os.ErrDeadlineExceeded
		case r := <-c.rx:
			if tm != nil {
				tm.Stop()
			}
			if r.e != nil {
				c.readErr = r.e
				return 0, r.e
			}
			c.pending = r.b
		}
	}
}
func (c *grpcConn) Write(p []byte) (int, error) {
	if e := acquire(c.ctx, c.wg, &c.wd); e != nil {
		return 0, e
	}
	defer func() { c.wg <- struct{}{} }()
	total := 0
	for len(p) > 0 {
		n := min(len(p), ChunkSize)
		r := sendRequest{append([]byte(nil), p[:n]...), make(chan error, 1)}
		sent := false
		for {
			t, changed := c.wd.snapshot()
			if !t.IsZero() && !time.Now().Before(t) {
				c.terminate()
				return total, os.ErrDeadlineExceeded
			}
			tm, expired := timer(t)
			var tx chan sendRequest
			if !sent {
				tx = c.tx
			}
			var reply chan error
			if sent {
				reply = r.result
			}
			select {
			case <-c.ctx.Done():
				if tm != nil {
					tm.Stop()
				}
				return total, net.ErrClosed
			case <-changed:
				if tm != nil {
					tm.Stop()
				}
				continue
			case <-expired:
				c.terminate()
				return total, os.ErrDeadlineExceeded
			case tx <- r:
				if tm != nil {
					tm.Stop()
				}
				sent = true
				continue
			case e := <-reply:
				if tm != nil {
					tm.Stop()
				}
				if e != nil {
					c.terminate()
					return total, e
				}
			}
			break
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
func (c *grpcConn) terminate() {
	c.once.Do(func() {
		c.cancel()
		if c.connection != nil {
			c.connection.Close()
		}
	})
}
func (c *grpcConn) Close() error {
	c.terminate()
	if c.connection != nil {
		<-c.joined
	}
	return nil
}
func (c *grpcConn) LocalAddr() net.Addr                { return c.local }
func (c *grpcConn) RemoteAddr() net.Addr               { return c.remote }
func (c *grpcConn) SetReadDeadline(t time.Time) error  { c.rd.set(t); return nil }
func (c *grpcConn) SetWriteDeadline(t time.Time) error { c.wd.set(t); return nil }
func (c *grpcConn) SetDeadline(t time.Time) error      { c.rd.set(t); c.wd.set(t); return nil }
func dialGRPC(ctx context.Context, dial DialFunc, address string, c cfg.Config, tc *tls.Config) (net.Conn, error) {
	creds := insecure.NewCredentials()
	if tc != nil {
		creds = &grpcTLSCredentials{base: credentials.NewTLS(tc), serverName: tc.ServerName}
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(creds), grpc.WithMaxHeaderListSize(cfg.MaxHeaders), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return dial(ctx, "tcp", address) }), grpc.WithDefaultCallOptions(grpc.ForceCodec(hunkCodec{}), grpc.MaxCallRecvMsgSize(MaxMessage+16), grpc.MaxCallSendMsgSize(MaxMessage+16))}
	if c.Host != "" {
		opts = append(opts, grpc.WithAuthority(c.Host))
	} else if tc != nil && tc.ServerName != "" {
		opts = append(opts, grpc.WithAuthority(tc.ServerName))
	}
	cc, e := grpc.NewClient("passthrough:///"+address, opts...)
	if e != nil {
		return nil, e
	}
	// Dial cancellation owns admission only. Published streams have independent
	// lifetime and are explicitly canceled by their net.Conn owner.
	life, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, cancel)
	admissionTimer := time.AfterFunc(HandshakeTimeout, cancel)
	s, e := cc.NewStream(life, &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}, "/"+c.Service()+"/Tun")
	stopped := stop()
	timed := !admissionTimer.Stop()
	if !stopped || timed || e != nil || ctx.Err() != nil {
		cancel()
		cc.Close()
		if e == nil {
			e = ctx.Err()
		}
		if e == nil {
			e = net.ErrClosed
		}
		return nil, e
	}
	return newGRPC(life, s, cancel, cc, transportAddr("grpc-client"), transportAddr(address)), nil
}

type transportAddr string

func (transportAddr) Network() string  { return "grpc" }
func (a transportAddr) String() string { return string(a) }

var _ net.Conn = (*grpcConn)(nil)
