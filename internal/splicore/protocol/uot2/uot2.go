// Package uot2 implements the public UDP-over-TCP v2 framing as a reusable
// packet adapter. SOCKS request addresses reuse the Core's existing codec.
package uot2

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/address"
)

const MagicHost = "sp.v2.udp-over-tcp.arpa"
const MaxDatagram = 65535

type Request struct {
	Connect     bool
	Destination access.Endpoint
}

func write(w io.Writer, b []byte) error {
	n, err := w.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	return err
}
func MarshalRequest(r Request) ([]byte, error) {
	if r.Connect && r.Destination.Validate() != nil {
		return nil, address.ErrAddress
	}
	b, err := address.MarshalSOCKS(r.Destination)
	if err != nil {
		return nil, err
	}
	flag := byte(0)
	if r.Connect {
		flag = 1
	}
	return append([]byte{flag}, b...), nil
}
func ReadRequest(r io.Reader) (Request, error) {
	var flag [1]byte
	if _, err := io.ReadFull(r, flag[:]); err != nil {
		return Request{}, err
	}
	if flag[0] > 1 {
		return Request{}, address.ErrAddress
	}
	dst, err := address.ReadSOCKS(r)
	if err != nil || flag[0] == 1 && dst.Validate() != nil {
		return Request{}, address.ErrAddress
	}
	return Request{Connect: flag[0] == 1, Destination: dst}, nil
}

func datagramAddress(dst access.Endpoint) ([]byte, error) {
	if dst.Validate() != nil {
		return nil, address.ErrAddress
	}
	b, err := address.MarshalSOCKS(dst)
	if err != nil {
		return nil, err
	}
	switch b[0] {
	case 1:
		b[0] = 0
	case 4:
		b[0] = 1
	case 3:
		b[0] = 2
	default:
		return nil, address.ErrAddress
	}
	return b, nil
}
func readDatagramAddress(r io.Reader) (access.Endpoint, error) {
	var tag [1]byte
	if _, err := io.ReadFull(r, tag[:]); err != nil {
		return access.Endpoint{}, err
	}
	switch tag[0] {
	case 0:
		tag[0] = 1
	case 1:
		tag[0] = 4
	case 2:
		tag[0] = 3
	default:
		return access.Endpoint{}, address.ErrAddress
	}
	dst, err := address.ReadSOCKS(io.MultiReader(bytes.NewReader(tag[:]), r))
	if err != nil || dst.Validate() != nil {
		return access.Endpoint{}, address.ErrAddress
	}
	return dst, nil
}

type Packet struct {
	conn            net.Conn
	request         Request
	server          bool
	readMu, writeMu sync.Mutex
	scratch         []byte
	once            sync.Once
}

func Client(conn net.Conn, request Request) (*Packet, error) {
	b, err := MarshalRequest(request)
	if err == nil {
		err = write(conn, b)
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ClientAfterRequest(conn, request)
}

// ClientAfterRequest wraps a stream whose initial proxy data already contained
// the marshalled request. This lets a parent protocol await its acknowledgement
// after the peer has read the UoT request, without sending the request twice.
func ClientAfterRequest(conn net.Conn, request Request) (*Packet, error) {
	if _, err := MarshalRequest(request); err != nil {
		conn.Close()
		return nil, err
	}
	return &Packet{conn: conn, request: request}, nil
}
func Server(conn net.Conn) (*Packet, error) {
	r, err := ReadRequest(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &Packet{conn: conn, request: r, server: true}, nil
}

func (p *Packet) ReadFrom(b []byte) (int, net.Addr, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()
	dst := p.request.Destination
	var err error
	if !p.request.Connect {
		dst, err = readDatagramAddress(p.conn)
	}
	var length [2]byte
	if err == nil {
		_, err = io.ReadFull(p.conn, length[:])
	}
	if err != nil {
		p.Close()
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	if p.scratch == nil {
		p.scratch = make([]byte, MaxDatagram)
	}
	if _, err = io.ReadFull(p.conn, p.scratch[:n]); err != nil {
		p.Close()
		return 0, nil, err
	}
	read := copy(b, p.scratch[:n])
	if read < n {
		return read, netaddr.UDP(dst), io.ErrShortBuffer
	}
	return read, netaddr.UDP(dst), nil
}
func (p *Packet) WriteTo(b []byte, a net.Addr) (int, error) {
	if len(b) > MaxDatagram {
		return 0, io.ErrShortBuffer
	}
	dst, err := netaddr.From(a)
	if err != nil || dst.Validate() != nil {
		return 0, address.ErrAddress
	}
	if p.request.Connect && !p.server && dst != p.request.Destination {
		return 0, address.ErrAddress
	}
	var data []byte
	if !p.request.Connect {
		data, err = datagramAddress(dst)
		if err != nil {
			return 0, err
		}
	}
	data = binary.BigEndian.AppendUint16(data, uint16(len(b)))
	data = append(data, b...)
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if err = write(p.conn, data); err != nil {
		p.Close()
		return 0, err
	}
	return len(b), nil
}
func (p *Packet) Close() error                       { var err error; p.once.Do(func() { err = p.conn.Close() }); return err }
func (p *Packet) LocalAddr() net.Addr                { return p.conn.LocalAddr() }
func (p *Packet) SetDeadline(t time.Time) error      { return p.conn.SetDeadline(t) }
func (p *Packet) SetReadDeadline(t time.Time) error  { return p.conn.SetReadDeadline(t) }
func (p *Packet) SetWriteDeadline(t time.Time) error { return p.conn.SetWriteDeadline(t) }

var _ net.PacketConn = (*Packet)(nil)
