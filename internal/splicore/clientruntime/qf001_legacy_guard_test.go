//go:build with_gvisor

package clientruntime

import (
	"os"
	"sync"
	"sync/atomic"

	"github.com/sagernet/gvisor/pkg/tcpip/stack"

	"github.com/sagernet/sing-tun"
)

// Pre-create the upstream endpoint before Start. Upstream Close assumes a
// dispatcher exists; a failed NewEndpoint would otherwise make Close unsafe.
type preparedEndpoint struct {
	tun.GVisorTun
	endpoint stack.LinkEndpoint
	options  stack.NICOptions
	write    chan struct{}
	stopped  atomic.Bool
}

func newPreparedEndpoint(device tun.GVisorTun, endpoint stack.LinkEndpoint, options stack.NICOptions) *preparedEndpoint {
	t := &preparedEndpoint{GVisorTun: device, endpoint: endpoint, options: options, write: make(chan struct{}, 1)}
	t.write <- struct{}{}
	return t
}

// The pinned NativeTun reuses device-owned iovec/header scratch. All explicit
// packet writers (filter, DNS return and TCP loopback) share this one owner.
// The token covers only WritePacket, through its synchronous writev return;
// callers retain their PacketBuffer until then. Stack processing stays concurrent.
func (t *preparedEndpoint) WritePacket(packet *stack.PacketBuffer) (int, error) {
	if t.stopped.Load() {
		return 0, os.ErrClosed
	}
	<-t.write
	defer func() { t.write <- struct{}{} }()
	if t.stopped.Load() {
		return 0, os.ErrClosed
	}
	return t.GVisorTun.WritePacket(packet)
}

func (t *preparedEndpoint) stopWrites() {
	t.stopped.Store(true)
	// Drain the outstanding syscall before the host owner can close/reuse its FD.
	<-t.write
	t.write <- struct{}{}
}

type ownedStack struct {
	tun.Stack
	writer *preparedEndpoint
	close  sync.Once
	err    error
}

func (s *ownedStack) Close() error {
	s.close.Do(func() {
		s.writer.stopWrites()
		s.err = s.Stack.Close()
	})
	return s.err
}

func (t *preparedEndpoint) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return t.endpoint, t.options, nil
}
