package testfixture

import (
	"bytes"
	"io"
	"net"
	"sync"

	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/address"
)

// SOCKSPacket wraps sockets created by the fixture; it owns their cleanup and
// uses RFC 1928's unfragmented datagram envelope, with per-call receive storage.
func SOCKSPacket(pc net.Conn, control net.Conn) net.PacketConn {
	return &socksPacket{Conn: pc, control: control}
}

type socksPacket struct {
	net.Conn
	control net.Conn
	once    sync.Once
	err     error
}

func (p *socksPacket) Close() error {
	p.once.Do(func() { _ = p.control.Close(); p.err = p.Conn.Close() })
	return p.err
}
func (p *socksPacket) WriteTo(b []byte, dst net.Addr) (int, error) {
	e, err := netaddr.From(dst)
	if err != nil {
		return 0, err
	}
	encoded, err := address.MarshalSOCKS(e)
	if err != nil {
		return 0, err
	}
	packet := append(append([]byte{0, 0, 0}, encoded...), b...)
	n, err := p.Conn.Write(packet)
	if err == nil && n != len(packet) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
func (p *socksPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	packet := make([]byte, 65535)
	n, err := p.Conn.Read(packet)
	if err != nil {
		return 0, nil, err
	}
	if n < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return 0, nil, address.ErrAddress
	}
	r := bytes.NewReader(packet[3:n])
	e, err := address.ReadSOCKS(r)
	if err != nil {
		return 0, nil, err
	}
	payload := packet[n-r.Len() : n]
	if len(payload) > len(b) {
		return 0, nil, io.ErrShortBuffer
	}
	return copy(b, payload), netaddr.UDP(e), nil
}
