package native

import "net"

// admissionPacket gates newly starting UDP listeners without owning protocol
// scratch or connection state. Protocol handles retain their own lifecycle.
type admissionPacket struct {
	net.PacketConn
	h packetAdmission
}
type packetAdmission interface {
	packetsAdmitted() bool
	packetsStopped()
}

func (p *admissionPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, a, err := p.PacketConn.ReadFrom(b)
		if err != nil {
			p.h.packetsStopped()
			return n, a, err
		}
		if p.h.packetsAdmitted() {
			return n, a, nil
		}
	}
}
