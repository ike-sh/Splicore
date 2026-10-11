// Package wire owns bounded VLESS v0 and XUDP application frames. The contract
// is specified by VLESS encoding and Mux.Cool metadata; Vision flow addons are bounded and explicit.
package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"google.golang.org/protobuf/encoding/protowire"
	"io"
	"net/netip"
)

const (
	TCP        byte = 1
	UDP        byte = 2
	Mux        byte = 3
	MaxPayload      = 65507
)

var ErrFrame = errors.New("invalid VLESS frame")
var ErrFlow = errors.New("VLESS flow unsupported")

func Write(w io.Writer, b []byte) error {
	n, e := w.Write(b)
	if e == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return e
}
func Address(dst access.Endpoint) ([]byte, error) {
	if dst.Validate() != nil {
		return nil, ErrFrame
	}
	b := binary.BigEndian.AppendUint16(nil, dst.Port)
	if ip, err := netip.ParseAddr(dst.Host); err == nil {
		ip = ip.Unmap()
		typ := byte(1)
		if ip.Is6() {
			typ = 3
		}
		b = append(b, typ)
		b = append(b, ip.AsSlice()...)
	} else {
		if len(dst.Host) > 255 {
			return nil, ErrFrame
		}
		b = append(b, 2, byte(len(dst.Host)))
		b = append(b, dst.Host...)
	}
	return b, nil
}
func ReadAddress(r io.Reader) (access.Endpoint, error) {
	var h [3]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return access.Endpoint{}, err
	}
	dst := access.Endpoint{Port: binary.BigEndian.Uint16(h[:2])}
	n := 0
	switch h[2] {
	case 1:
		n = 4
	case 3:
		n = 16
	case 2:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return dst, err
		}
		n = int(length[0])
		if n == 0 {
			return dst, ErrFrame
		}
	default:
		return dst, ErrFrame
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return dst, err
	}
	if h[2] == 2 {
		dst.Host = string(b)
		if ip, err := netip.ParseAddr(dst.Host); err == nil {
			dst.Host = ip.Unmap().String()
		}
	} else {
		ip, ok := netip.AddrFromSlice(b)
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
func readAddons(r io.Reader) (string, error) {
	var result string
	seen := false
	var length [1]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return "", err
	}
	b := make([]byte, int(length[0]))
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	for len(b) > 0 {
		field, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return "", ErrFrame
		}
		b = b[n:]
		if field == 1 {
			if typ != protowire.BytesType {
				return "", ErrFrame
			}
			flow, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return "", ErrFrame
			}
			if seen {
				return "", ErrFrame
			}
			seen = true
			result = string(flow)
			if result != "" && result != "xtls-rprx-vision" {
				return "", ErrFlow
			}
			b = b[n:]
		} else {
			n := protowire.ConsumeFieldValue(field, typ, b)
			if n < 0 {
				return "", ErrFrame
			}
			b = b[n:]
		}
	}
	return result, nil
}

type Request struct {
	Flow        string
	UUID        [16]byte
	Command     byte
	Destination access.Endpoint
}

func ReadRequest(r io.Reader) (Request, error) {
	var h [17]byte
	var q Request
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return q, err
	}
	if h[0] != 0 {
		return q, ErrFrame
	}
	copy(q.UUID[:], h[1:])
	flow, err := readAddons(r)
	if err != nil {
		return q, err
	}
	q.Flow = flow
	var cmd [1]byte
	if _, err := io.ReadFull(r, cmd[:]); err != nil {
		return q, err
	}
	q.Command = cmd[0]
	switch q.Command {
	case TCP, UDP:
		var err error
		q.Destination, err = ReadAddress(r)
		return q, err
	case Mux:
		return q, nil
	default:
		return q, ErrFrame
	}
}
func WriteRequest(w io.Writer, q Request) error {
	b := append([]byte{0}, q.UUID[:]...)
	var addon []byte
	if q.Flow != "" {
		if q.Flow != "xtls-rprx-vision" {
			return ErrFlow
		}
		addon = protowire.AppendTag(addon, 1, protowire.BytesType)
		addon = protowire.AppendString(addon, q.Flow)
	}
	b = append(b, byte(len(addon)))
	b = append(b, addon...)
	b = append(b, q.Command)
	switch q.Command {
	case TCP, UDP:
		a, err := Address(q.Destination)
		if err != nil {
			return err
		}
		b = append(b, a...)
	case Mux:
	default:
		return ErrFrame
	}
	return Write(w, b)
}
func ReadResponse(r io.Reader) error {
	var version [1]byte
	if _, err := io.ReadFull(r, version[:]); err != nil {
		return err
	}
	if version[0] != 0 {
		return ErrFrame
	}
	flow, e := readAddons(r)
	if e != nil {
		return e
	}
	if flow != "" {
		return ErrFlow
	}
	return nil
}

// Frame is a bounded XUDP/Mux.Cool message. Payload is newly allocated and
// transferred to a per-session queue. Frame parser state belongs to one reader.
type Frame struct {
	Session                  uint16
	Status, Options, Network byte
	Destination              access.Endpoint
	Payload                  []byte
}

func ReadFrame(r io.Reader) (Frame, error) {
	var f Frame
	var length [2]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return f, err
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	if n < 4 || n > 512 {
		return f, ErrFrame
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return f, err
	}
	f.Session = binary.BigEndian.Uint16(b)
	f.Status = b[2]
	f.Options = b[3]
	if f.Status < 1 || f.Status > 4 || f.Options&^byte(3) != 0 {
		return f, ErrFrame
	}
	if f.Status == 1 || f.Status == 2 && len(b) > 4 && b[4] == 2 {
		if len(b) < 8 {
			return f, ErrFrame
		}
		f.Network = b[4]
		var err error
		f.Destination, err = ReadAddress(bytes.NewReader(b[5:]))
		if err != nil {
			return f, err
		}
	}
	if f.Options&1 != 0 {
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return f, err
		}
		n := int(binary.BigEndian.Uint16(length[:]))
		if n > MaxPayload {
			return f, ErrFrame
		}
		f.Payload = make([]byte, n)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return f, err
		}
	}
	return f, nil
}
func WriteFrame(w io.Writer, f Frame) error {
	b, err := EncodeFrame(f)
	if err != nil {
		return err
	}
	return Write(w, b)
}

// EncodeFrame validates before any wire commit. Transport owners use the
// resulting complete frame to track the byte count of a possibly partial Write.
func EncodeFrame(f Frame) ([]byte, error) {
	if f.Status < 1 || f.Status > 4 || len(f.Payload) > MaxPayload {
		return nil, ErrFrame
	}
	meta := binary.BigEndian.AppendUint16(nil, f.Session)
	options := f.Options
	if f.Payload != nil {
		options |= 1
	}
	meta = append(meta, f.Status, options)
	if f.Destination != (access.Endpoint{}) {
		a, err := Address(f.Destination)
		if err != nil {
			return nil, err
		}
		meta = append(meta, f.Network)
		meta = append(meta, a...)
	} else if f.Status == 1 {
		return nil, ErrFrame
	}
	if len(meta) > 512 {
		return nil, ErrFrame
	}
	b := binary.BigEndian.AppendUint16(nil, uint16(len(meta)))
	b = append(b, meta...)
	if options&1 != 0 {
		b = binary.BigEndian.AppendUint16(b, uint16(len(f.Payload)))
		b = append(b, f.Payload...)
	}
	return b, nil
}
