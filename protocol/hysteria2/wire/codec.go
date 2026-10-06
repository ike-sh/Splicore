// Package wire implements only the documented Hysteria2 application framing.
// QUIC, TLS, congestion control and crypto primitives belong to mature libraries.
package wire

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"time"

	"github.com/apernet/quic-go/quicvarint"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

const TCPRequest = 0x401
const MaxUDP = 4096

var ErrFrame = errors.New("invalid Hysteria2 frame")
var ErrRejected = errors.New("Hysteria2 request rejected")

func Endpoint(address string) (access.Endpoint, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return access.Endpoint{}, ErrFrame
	}
	n, err := strconv.ParseUint(port, 10, 16)
	dst := access.Endpoint{Host: host, Port: uint16(n)}
	if err != nil || dst.Validate() != nil {
		return access.Endpoint{}, ErrFrame
	}
	return dst, nil
}
func Address(dst access.Endpoint) string {
	return net.JoinHostPort(dst.Host, strconv.Itoa(int(dst.Port)))
}

// Padding preserves the established half-open length range [low, high).
func Padding(low, high int) (string, error) {
	return padding(rand.Reader, low, high)
}

func padding(random io.Reader, low, high int) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if low < 0 || high <= low {
		return "", ErrFrame
	}
	n, err := rand.Int(random, big.NewInt(int64(high-low)))
	if err != nil {
		return "", err
	}
	b := make([]byte, low+int(n.Int64()))
	var sample [256]byte
	for used := 0; used < len(b); {
		count := min(len(sample), len(b)-used)
		if _, err := io.ReadFull(random, sample[:count]); err != nil {
			return "", err
		}
		for _, v := range sample[:count] {
			// 248 = 4 * 62. Reject the excess eight values before reducing.
			if v < 248 {
				b[used] = alphabet[int(v)%len(alphabet)]
				used++
			}
		}
	}
	return string(b), nil
}
func write(w io.Writer, b []byte) error {
	n, err := w.Write(b)
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}
func field(r io.Reader, max int, empty bool) ([]byte, error) {
	n, err := quicvarint.Read(quicvarint.NewReader(r))
	if err != nil {
		return nil, err
	}
	if n > uint64(max) || n == 0 && !empty {
		return nil, ErrFrame
	}
	b := make([]byte, int(n))
	_, err = io.ReadFull(r, b)
	return b, err
}
func skipPadding(r io.Reader) error {
	n, err := quicvarint.Read(quicvarint.NewReader(r))
	if err != nil {
		return err
	}
	if n > 4096 {
		return ErrFrame
	}
	_, err = io.CopyN(io.Discard, r, int64(n))
	return err
}

// ReadRequest starts after the HTTP/3 dispatcher has consumed frame type 0x401.
func ReadRequest(r io.Reader) (access.Endpoint, error) {
	b, err := field(r, 2048, false)
	if err != nil {
		return access.Endpoint{}, err
	}
	if err := skipPadding(r); err != nil {
		return access.Endpoint{}, err
	}
	return Endpoint(string(b))
}
func WriteRequest(w io.Writer, dst access.Endpoint) error {
	if dst.Validate() != nil {
		return ErrFrame
	}
	address := Address(dst)
	padding, err := Padding(64, 512)
	if err != nil {
		return err
	}
	b := quicvarint.Append(nil, TCPRequest)
	b = quicvarint.Append(b, uint64(len(address)))
	b = append(b, address...)
	b = quicvarint.Append(b, uint64(len(padding)))
	b = append(b, padding...)
	return write(w, b)
}
func ReadResponse(r io.Reader) error {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return err
	}
	if _, err := field(r, 2048, true); err != nil {
		return err
	}
	if err := skipPadding(r); err != nil {
		return err
	}
	if status[0] != 0 {
		return ErrRejected
	}
	return nil
}
func WriteResponse(w io.Writer, ok bool) error {
	status := byte(1)
	message := "Target unavailable"
	if ok {
		status = 0
		message = "Connected"
	}
	padding, err := Padding(128, 1024)
	if err != nil {
		return err
	}
	b := quicvarint.Append([]byte{status}, uint64(len(message)))
	b = append(b, message...)
	b = quicvarint.Append(b, uint64(len(padding)))
	b = append(b, padding...)
	return write(w, b)
}

// Datagram owns its payload after DecodeDatagram; input storage may be reused.
type Datagram struct {
	Session      uint32
	Packet       uint16
	Index, Count byte
	Destination  access.Endpoint
	Payload      []byte
}

func DecodeDatagram(b []byte) (Datagram, error) {
	if len(b) < 9 {
		return Datagram{}, ErrFrame
	}
	d := Datagram{Session: binary.BigEndian.Uint32(b), Packet: binary.BigEndian.Uint16(b[4:]), Index: b[6], Count: b[7]}
	if d.Count == 0 || d.Index >= d.Count {
		return d, ErrFrame
	}
	r := bytes.NewReader(b[8:])
	address, err := field(r, 2048, false)
	if err != nil {
		return d, err
	}
	d.Destination, err = Endpoint(string(address))
	if err != nil {
		return d, err
	}
	if r.Len() == 0 || r.Len() > MaxUDP {
		return d, ErrFrame
	}
	d.Payload = make([]byte, r.Len())
	_, err = io.ReadFull(r, d.Payload)
	return d, err
}
func EncodeDatagram(d Datagram) ([]byte, error) {
	if d.Count == 0 || d.Index >= d.Count || d.Destination.Validate() != nil || len(d.Payload) == 0 || len(d.Payload) > MaxUDP {
		return nil, ErrFrame
	}
	address := Address(d.Destination)
	b := binary.BigEndian.AppendUint32(nil, d.Session)
	b = binary.BigEndian.AppendUint16(b, d.Packet)
	b = append(b, d.Index, d.Count)
	b = quicvarint.Append(b, uint64(len(address)))
	b = append(b, address...)
	return append(b, d.Payload...), nil
}

// Fragments bounds wire messages before SendDatagram. Payload bytes remain
// caller-owned until all synchronous sends return; encoded frames are fresh.
func Fragments(session uint32, packet uint16, dst access.Endpoint, payload []byte) ([][]byte, error) {
	if len(payload) == 0 || len(payload) > MaxUDP {
		return nil, ErrFrame
	}
	// 1197 is the payload allowance in a 1200-byte QUIC DATAGRAM frame.
	size := 1197 - 8 - int(quicvarint.Len(uint64(len(Address(dst))))) - len(Address(dst))
	if size <= 0 {
		return nil, ErrFrame
	}
	count := (len(payload) + size - 1) / size
	var frames [][]byte
	for i := 0; i < count; i++ {
		b, err := EncodeDatagram(Datagram{session, packet, byte(i), byte(count), dst, payload[i*size : min((i+1)*size, len(payload))]})
		if err != nil {
			return nil, err
		}
		frames = append(frames, b)
	}
	return frames, nil
}

// Assembly belongs to one ReceiveDatagram goroutine. It never shares scratch
// bytes with packet workers, retains at most 128 incomplete datagrams, and
// bounds each reassembled payload by the established 4096-byte capability.
type Assembly struct{ pending map[uint64]*parts }
type parts struct {
	dst            access.Endpoint
	count          byte
	payloads       [][]byte
	size, received int
	expires        time.Time
}

func (a *Assembly) Add(d Datagram) (Datagram, bool) {
	if d.Count == 0 || d.Index >= d.Count || len(d.Payload) == 0 || len(d.Payload) > MaxUDP || d.Destination.Validate() != nil {
		return Datagram{}, false
	}
	if d.Count == 1 {
		d.Payload = bytes.Clone(d.Payload)
		return d, true
	}
	if a.pending == nil {
		a.pending = map[uint64]*parts{}
	}
	key := uint64(d.Session)<<16 | uint64(d.Packet)
	p := a.pending[key]
	if p != nil && time.Now().After(p.expires) {
		delete(a.pending, key)
		p = nil
	}
	if p == nil {
		if len(a.pending) >= 128 {
			clear(a.pending)
		}
		p = &parts{dst: d.Destination, count: d.Count, payloads: make([][]byte, int(d.Count)), expires: time.Now().Add(5 * time.Second)}
		a.pending[key] = p
	}
	if p.dst != d.Destination || p.count != d.Count {
		delete(a.pending, key)
		return Datagram{}, false
	}
	if p.payloads[d.Index] != nil {
		return Datagram{}, false
	}
	p.size += len(d.Payload)
	if p.size > MaxUDP {
		delete(a.pending, key)
		return Datagram{}, false
	}
	p.payloads[d.Index] = bytes.Clone(d.Payload)
	p.received++
	if p.received != int(p.count) {
		return Datagram{}, false
	}
	d.Payload = make([]byte, 0, p.size)
	for _, b := range p.payloads {
		d.Payload = append(d.Payload, b...)
	}
	d.Index = 0
	d.Count = 1
	delete(a.pending, key)
	return d, true
}
