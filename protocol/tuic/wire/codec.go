// Package wire owns TUIC v5 application commands as described by the official
// SPEC.md. It implements no QUIC, TLS or cryptographic primitive.
package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

const (
	Version      byte = 5
	Authenticate byte = iota - 1
	Connect
	Packet
	Dissociate
	Heartbeat
	MaxPayload = 65507
)

var ErrFrame = errors.New("invalid TUIC v5 command")

func Head(r io.Reader) (byte, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	if b[0] != Version || b[1] > Heartbeat {
		return 0, ErrFrame
	}
	return b[1], nil
}
func Write(w io.Writer, b []byte) error {
	n, err := w.Write(b)
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}
func Address(dst access.Endpoint) ([]byte, error) {
	if dst.Validate() != nil {
		return nil, ErrFrame
	}
	var b []byte
	if ip, err := netip.ParseAddr(dst.Host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			b = append([]byte{1}, ip.AsSlice()...)
		} else {
			b = append([]byte{2}, ip.AsSlice()...)
		}
	} else {
		if len(dst.Host) > 255 {
			return nil, ErrFrame
		}
		b = append([]byte{0, byte(len(dst.Host))}, dst.Host...)
	}
	return binary.BigEndian.AppendUint16(b, dst.Port), nil
}
func ReadAddress(r io.Reader, none bool) (access.Endpoint, error) {
	var typ [1]byte
	if _, err := io.ReadFull(r, typ[:]); err != nil {
		return access.Endpoint{}, err
	}
	n := 0
	switch typ[0] {
	case 255:
		if none {
			return access.Endpoint{}, nil
		}
		return access.Endpoint{}, ErrFrame
	case 0:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return access.Endpoint{}, err
		}
		n = int(length[0])
		if n == 0 {
			return access.Endpoint{}, ErrFrame
		}
	case 1:
		n = 4
	case 2:
		n = 16
	default:
		return access.Endpoint{}, ErrFrame
	}
	b := make([]byte, n+2)
	if _, err := io.ReadFull(r, b); err != nil {
		return access.Endpoint{}, err
	}
	dst := access.Endpoint{Port: binary.BigEndian.Uint16(b[n:])}
	if typ[0] == 0 {
		dst.Host = string(b[:n])
		if ip, err := netip.ParseAddr(dst.Host); err == nil {
			dst.Host = ip.Unmap().String()
		}
	} else {
		ip, ok := netip.AddrFromSlice(b[:n])
		if !ok {
			return dst, ErrFrame
		}
		dst.Host = ip.Unmap().String()
	}
	if dst.Validate() != nil {
		return dst, ErrFrame
	}
	return dst, nil
}
func ConnectFrame(dst access.Endpoint) ([]byte, error) {
	a, err := Address(dst)
	return append([]byte{Version, Connect}, a...), err
}
func AuthFrame(uuid [16]byte, token []byte) ([]byte, error) {
	if len(token) != 32 {
		return nil, ErrFrame
	}
	b := append([]byte{Version, Authenticate}, uuid[:]...)
	return append(b, token...), nil
}

// Datagram owns payload storage and carries a semantic destination. Non-first
// fragments may omit their destination; assembly restores it from fragment 0.
type Datagram struct {
	Association, ID uint16
	Count, Index    byte
	Destination     access.Endpoint
	Payload         []byte
}

func Decode(b []byte) (Datagram, error) {
	var d Datagram
	if len(b) < 11 || b[0] != Version || b[1] != Packet {
		return d, ErrFrame
	}
	d.Association = binary.BigEndian.Uint16(b[2:])
	d.ID = binary.BigEndian.Uint16(b[4:])
	d.Count = b[6]
	d.Index = b[7]
	size := int(binary.BigEndian.Uint16(b[8:]))
	if d.Count == 0 || d.Index >= d.Count || size > MaxPayload {
		return d, ErrFrame
	}
	r := bytes.NewReader(b[10:])
	dst, err := ReadAddress(r, d.Index > 0)
	if err != nil || r.Len() != size {
		return d, ErrFrame
	}
	d.Destination = dst
	d.Payload = make([]byte, size)
	_, err = io.ReadFull(r, d.Payload)
	return d, err
}
func Encode(d Datagram) ([]byte, error) {
	if d.Count == 0 || d.Index >= d.Count || len(d.Payload) > MaxPayload {
		return nil, ErrFrame
	}
	a := []byte{255}
	var err error
	if d.Destination != (access.Endpoint{}) {
		a, err = Address(d.Destination)
	} else if d.Index == 0 {
		return nil, ErrFrame
	}
	if err != nil {
		return nil, err
	}
	b := binary.BigEndian.AppendUint16([]byte{Version, Packet}, d.Association)
	b = binary.BigEndian.AppendUint16(b, d.ID)
	b = append(b, d.Count, d.Index)
	b = binary.BigEndian.AppendUint16(b, uint16(len(d.Payload)))
	b = append(b, a...)
	return append(b, d.Payload...), nil
}
func Fragments(association, id uint16, dst access.Endpoint, payload []byte) ([][]byte, error) {
	if len(payload) > MaxPayload {
		return nil, ErrFrame
	}
	address, err := Address(dst)
	if err != nil {
		return nil, err
	}
	// A conservative size fits the minimum QUIC path MTU, including framing.
	size := 1150 - 10 - len(address)
	count := max(1, (len(payload)+size-1)/size)
	if count > 255 {
		return nil, ErrFrame
	}
	result := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		destination := dst
		if i > 0 {
			destination = access.Endpoint{}
		}
		b, err := Encode(Datagram{association, id, byte(count), byte(i), destination, payload[min(i*size, len(payload)):min((i+1)*size, len(payload))]})
		if err != nil {
			return nil, err
		}
		result = append(result, b)
	}
	return result, nil
}

// Assembly has exactly one dispatcher owner. Untrusted input can retain at
// most 128 incomplete packets, with a 65507-byte payload bound and expiry.
type Assembly struct{ pending map[uint32]*parts }
type parts struct {
	count          byte
	dst            access.Endpoint
	payloads       [][]byte
	present        []bool
	received, size int
	expires        time.Time
}

func (a *Assembly) Add(d Datagram) (Datagram, bool) {
	if d.Count == 0 || d.Index >= d.Count || len(d.Payload) > MaxPayload {
		return Datagram{}, false
	}
	if d.Count == 1 {
		if d.Destination.Validate() != nil {
			return Datagram{}, false
		}
		d.Payload = bytes.Clone(d.Payload)
		return d, true
	}
	if a.pending == nil {
		a.pending = map[uint32]*parts{}
	}
	key := uint32(d.Association)<<16 | uint32(d.ID)
	p := a.pending[key]
	if p != nil && time.Now().After(p.expires) {
		delete(a.pending, key)
		p = nil
	}
	if p == nil {
		if len(a.pending) >= 128 {
			clear(a.pending)
		}
		p = &parts{count: d.Count, payloads: make([][]byte, d.Count), present: make([]bool, d.Count), expires: time.Now().Add(5 * time.Second)}
		a.pending[key] = p
	}
	if p.count != d.Count || p.present[d.Index] {
		return Datagram{}, false
	}
	if d.Index == 0 {
		if d.Destination.Validate() != nil {
			delete(a.pending, key)
			return Datagram{}, false
		}
		p.dst = d.Destination
	} else if d.Destination != (access.Endpoint{}) && p.dst != (access.Endpoint{}) && p.dst != d.Destination {
		delete(a.pending, key)
		return Datagram{}, false
	}
	p.size += len(d.Payload)
	if p.size > MaxPayload {
		delete(a.pending, key)
		return Datagram{}, false
	}
	p.payloads[d.Index] = bytes.Clone(d.Payload)
	p.present[d.Index] = true
	p.received++
	if p.received != int(p.count) {
		return Datagram{}, false
	}
	delete(a.pending, key)
	if p.dst.Validate() != nil {
		return Datagram{}, false
	}
	d.Destination = p.dst
	d.Payload = make([]byte, 0, p.size)
	for _, payload := range p.payloads {
		d.Payload = append(d.Payload, payload...)
	}
	d.Index = 0
	d.Count = 1
	return d, true
}
