// Package nativetun owns the client TUN packet and netstack lifetime. Backend
// types are confined to the implementation; dispatchers use standard Go I/O.
package nativetun

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

// Device is borrowed from the host journal. Interrupt wakes all pending I/O
// without releasing the journal-owned device. Read/Write consume one IP packet
// and may borrow call bytes only until return. The runtime serializes writes.
type Device interface {
	io.ReadWriteCloser
	Start() error
	Interrupt() error
}

// Dispatcher calls are synchronous. Returning releases the flow and its
// generation ownership. Implementations must honor ctx and connection Close.
type Dispatcher interface {
	TCP(context.Context, net.Conn, netip.AddrPort, netip.AddrPort)
	UDP(context.Context, net.Conn, netip.AddrPort, netip.AddrPort)
}

type Options struct {
	MTU        uint32
	Addresses  []netip.Addr // immutable local interface identities for ICMP policy
	Dispatcher Dispatcher
}

type State string

const (
	Prepared State = "prepared"
	Starting State = "starting"
	Running  State = "running"
	Draining State = "draining"
	Stopping State = "stopping"
	Stopped  State = "stopped"
	Failed   State = "failed"
)

var (
	ErrUnavailable = errors.New("native TUN unavailable")
	ErrStarted     = errors.New("native TUN already started")
	ErrInvalid     = errors.New("invalid native TUN options")
)

type backend interface{ close() }

type Runtime struct {
	device    Device
	options   Options
	ctx       context.Context
	cancel    context.CancelFunc
	operation sync.Mutex
	mu        sync.Mutex
	state     State
	backend   backend
	err       error
	done      chan struct{}
	writer    *packetWriter
}

func New(parent context.Context, device Device, options Options) (*Runtime, error) {
	if device == nil || options.Dispatcher == nil || options.MTU < 1280 || options.MTU > 9000 {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithCancel(parent)
	options.Addresses = append([]netip.Addr(nil), options.Addresses...)
	r := &Runtime{device: device, options: options, ctx: ctx, cancel: cancel, state: Prepared, done: make(chan struct{}), writer: newPacketWriter(device)}
	go r.shutdown()
	return r, nil
}

func (r *Runtime) Start() error {
	r.operation.Lock()
	defer r.operation.Unlock()
	r.mu.Lock()
	if r.state != Prepared {
		r.mu.Unlock()
		return ErrStarted
	}
	if err := r.ctx.Err(); err != nil {
		r.state, r.err = Failed, err
		r.mu.Unlock()
		return err
	}
	r.state = Starting
	r.mu.Unlock()
	b, err := startBackend(r)
	if err == nil {
		err = r.ctx.Err()
	}
	r.mu.Lock()
	r.backend = b
	if err != nil {
		r.state, r.err = Failed, errors.Join(r.err, err)
	} else {
		r.state = Running
	}
	r.mu.Unlock()
	if err != nil {
		r.cancel()
	}
	return err
}

func (r *Runtime) State() State { r.mu.Lock(); defer r.mu.Unlock(); return r.state }

// Close stops admission, wakes I/O, joins all borrowers and destroys the stack.
// It never closes the device; host restoration releases that ownership later.
func (r *Runtime) Close() error {
	r.cancel()
	return r.Wait()
}

// One lifecycle worker is owned from New to Wait. Start publication and cleanup
// are serialized; neither a packet worker nor a cancellation callback can
// accidentally join itself.
func (r *Runtime) shutdown() {
	<-r.ctx.Done()
	r.operation.Lock()
	defer r.operation.Unlock()
	r.mu.Lock()
	failed := r.state == Failed
	r.state = Draining
	r.mu.Unlock()
	r.writer.reject()
	var err error
	if r.backend != nil {
		err = r.device.Interrupt()
	}
	r.writer.drain()
	r.mu.Lock()
	r.state = Stopping
	r.mu.Unlock()
	if r.backend != nil {
		r.backend.close()
	}
	r.mu.Lock()
	r.err = errors.Join(r.err, err)
	if failed || r.err != nil {
		r.state = Failed
	} else {
		r.state = Stopped
	}
	r.mu.Unlock()
	close(r.done)
}

func (r *Runtime) Wait() error {
	<-r.done
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// packetWriter enforces a single synchronous syscall per borrowed device.
// Every caller retains its own bytes until WritePacket returns.
type packetWriter struct {
	device  io.Writer
	token   chan struct{}
	stopped atomic.Bool
}

func newPacketWriter(device io.Writer) *packetWriter {
	w := &packetWriter{device: device, token: make(chan struct{}, 1)}
	w.token <- struct{}{}
	return w
}

func (w *packetWriter) WritePacket(p []byte) (int, error) {
	if w.stopped.Load() {
		return 0, net.ErrClosed
	}
	<-w.token
	defer func() { w.token <- struct{}{} }()
	if w.stopped.Load() {
		return 0, net.ErrClosed
	}
	n, err := w.device.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}
func (w *packetWriter) reject() { w.stopped.Store(true) }
func (w *packetWriter) drain()  { <-w.token; w.token <- struct{}{} }
