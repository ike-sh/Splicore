//go:build windows && with_gvisor

package hostnetwork

import (
	"context"
	"sync"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing-tun"
)

var _ tun.GVisorTun = (*windowsWintun)(nil)

type ownedWintunEndpoint struct {
	*channel.Endpoint
	device  *windowsWintun
	ctx     context.Context
	cancel  context.CancelFunc
	start   sync.Once
	close   sync.Once
	wg      sync.WaitGroup
	control sync.Mutex
	closing bool
}

func (d *windowsWintun) WritePacket(p *stack.PacketBuffer) (int, error) {
	var packet []byte
	for _, part := range p.AsSlices() {
		packet = append(packet, part...)
	}
	return d.Write(packet)
}
func (d *windowsWintun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	ctx, cancel := context.WithCancel(context.Background())
	e := &ownedWintunEndpoint{Endpoint: channel.New(256, d.mtu, ""), device: d, ctx: ctx, cancel: cancel}
	return e, stack.NICOptions{}, nil
}
func (e *ownedWintunEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.control.Lock()
	defer e.control.Unlock()
	if e.closing {
		return
	}
	e.Endpoint.Attach(dispatcher)
	if dispatcher == nil {
		return
	}
	e.start.Do(func() { e.wg.Add(2); go e.receive(); go e.send() })
}
func (e *ownedWintunEndpoint) interrupt() {
	e.cancel()
	e.device.mu.Lock()
	s := e.device.session
	e.device.mu.Unlock()
	if s != nil {
		_ = s.Interrupt()
	}
}
func (e *ownedWintunEndpoint) receive() {
	defer e.wg.Done()
	defer e.interrupt()
	data := make([]byte, 65535)
	for e.ctx.Err() == nil {
		n, err := e.device.Read(data)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		var protocol tcpip.NetworkProtocolNumber
		switch header.IPVersion(data[:n]) {
		case 4:
			protocol = header.IPv4ProtocolNumber
		case 6:
			protocol = header.IPv6ProtocolNumber
		default:
			continue
		}
		// The channel/stack owns this packet copy past the next ring read.
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), data[:n]...)), IsForwardedPacket: true})
		e.InjectInbound(protocol, p)
		p.DecRef()
	}
}
func (e *ownedWintunEndpoint) send() {
	defer e.wg.Done()
	defer e.interrupt()
	for {
		p := e.ReadContext(e.ctx)
		if p == nil {
			return
		}
		_, err := e.device.WritePacket(p)
		p.DecRef()
		if err != nil {
			return
		}
	}
}
func (e *ownedWintunEndpoint) Close() {
	e.close.Do(func() {
		e.control.Lock()
		e.closing = true
		e.interrupt()
		e.control.Unlock()
		e.wg.Wait()
		e.Endpoint.Close()
	})
}
func (e *ownedWintunEndpoint) Wait() { e.wg.Wait() }
