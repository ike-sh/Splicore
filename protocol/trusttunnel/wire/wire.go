// Package wire implements TrustTunnel 1.0 from the public protocol specification.
// It contains no HTTP session, routing, DNS or socket policy.
package wire

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
)

const MaxPayload = 65507
const MaxFrame = 36 + 1 + 255 + MaxPayload

var ErrFrame = errors.New("trusttunnel: invalid bounded wire frame")
var ErrAuthority = errors.New("trusttunnel: invalid authority")
var ErrAuth = errors.New("trusttunnel: invalid Basic credentials")

func Authority(s string) (string, error) {
	if len(s) > 512 || strings.ContainsAny(s, "/\\@?#%") || strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", ErrAuthority
	}
	h, p, err := net.SplitHostPort(s)
	n, e := strconv.ParseUint(p, 10, 16)
	if err != nil || e != nil || n == 0 || h == "" || strings.HasPrefix(h, "_") || strconv.FormatUint(n, 10) != p {
		return "", ErrAuthority
	}
	if ip, e := netip.ParseAddr(h); e == nil {
		ip = ip.Unmap()
		if ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
			return "", ErrAuthority
		}
		h = ip.Unmap().String()
	} else {
		if len(h) > 253 || strings.Contains(h, ":") {
			return "", ErrAuthority
		}
		for _, label := range strings.Split(strings.TrimSuffix(h, "."), ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", ErrAuthority
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
					return "", ErrAuthority
				}
			}
		}
		// Reject alternate textual numeric IP forms rather than delegating their interpretation.
		if strings.Trim(h, "0123456789.") == "" {
			return "", ErrAuthority
		}
		h = strings.ToLower(h)
	}
	return net.JoinHostPort(h, p), nil
}

func Credentials(username, password string) bool {
	return username != "" && password != "" && len(username) <= 255 && len(password) <= 1024 && !strings.ContainsAny(username, ":\x00\r\n") && !strings.ContainsAny(password, "\x00\r\n")
}
func Authorization(u, p string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p))
}
func Basic(value string) (string, string, error) {
	if len(value) > 1800 || len(value) < 7 || !strings.EqualFold(value[:6], "Basic ") {
		return "", "", ErrAuth
	}
	b, err := base64.StdEncoding.Strict().DecodeString(value[6:])
	if err != nil {
		return "", "", ErrAuth
	}
	u, p, ok := strings.Cut(string(b), ":")
	if !ok || !Credentials(u, p) {
		return "", "", ErrAuth
	}
	return u, p, nil
}

func PutIP(dst []byte, ip netip.Addr) error {
	if len(dst) < 16 || !ip.IsValid() || ip.Zone() != "" {
		return ErrFrame
	}
	ip = ip.Unmap()
	clear(dst[:16])
	if ip.Is4() {
		b := ip.As4()
		copy(dst[12:16], b[:])
	} else {
		b := ip.As16()
		copy(dst[:16], b[:])
	}
	return nil
}
func IP(b []byte) (netip.Addr, error) {
	if len(b) != 16 {
		return netip.Addr{}, ErrFrame
	}
	a := [16]byte(b)
	ip := netip.AddrFrom16(a)
	zero := true
	for _, v := range a[:12] {
		zero = zero && v == 0
	}
	if zero && ip != netip.IPv6Loopback() {
		ip = netip.AddrFrom4([4]byte(a[12:]))
	}
	return ip.Unmap(), nil
}

type Datagram struct {
	Source, Destination netip.AddrPort
	App                 string
	Payload             []byte
}

func validEndpoint(a netip.AddrPort) bool {
	return a.IsValid() && a.Port() != 0 && !a.Addr().IsUnspecified() && !a.Addr().IsMulticast() && a.Addr().Zone() == ""
}
func EncodeUDP(d Datagram, outgoing bool) ([]byte, error) {
	if !validEndpoint(d.Source) || !validEndpoint(d.Destination) || len(d.App) > 255 || len(d.Payload) > MaxPayload || !outgoing && d.App != "" {
		return nil, ErrFrame
	}
	n := 36 + len(d.Payload)
	if outgoing {
		n += 1 + len(d.App)
	}
	b := make([]byte, 4+n)
	binary.BigEndian.PutUint32(b, uint32(n))
	_ = PutIP(b[4:20], d.Source.Addr())
	binary.BigEndian.PutUint16(b[20:], d.Source.Port())
	_ = PutIP(b[22:38], d.Destination.Addr())
	binary.BigEndian.PutUint16(b[38:], d.Destination.Port())
	i := 40
	if outgoing {
		b[i] = byte(len(d.App))
		i++
		copy(b[i:], d.App)
		i += len(d.App)
	}
	copy(b[i:], d.Payload)
	return b, nil
}
func DecodeUDP(b []byte, outgoing bool) (Datagram, error) {
	var d Datagram
	minimum := 36
	if outgoing {
		minimum++
	}
	if len(b) < minimum || len(b) > MaxFrame {
		return d, ErrFrame
	}
	s, e := IP(b[:16])
	if e != nil {
		return d, e
	}
	t, e := IP(b[18:34])
	if e != nil {
		return d, e
	}
	d.Source = netip.AddrPortFrom(s, binary.BigEndian.Uint16(b[16:]))
	d.Destination = netip.AddrPortFrom(t, binary.BigEndian.Uint16(b[34:]))
	i := 36
	if outgoing {
		n := int(b[i])
		i++
		if n > len(b)-i {
			return Datagram{}, ErrFrame
		}
		d.App = string(b[i : i+n])
		i += n
	}
	if !validEndpoint(d.Source) || !validEndpoint(d.Destination) || len(b)-i > MaxPayload {
		return Datagram{}, ErrFrame
	}
	d.Payload = b[i:]
	return d, nil
}

// ReadUDP validates the declared size before allocating. EOF in any frame is fatal.
func ReadUDP(r io.Reader, outgoing bool) (Datagram, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return Datagram{}, err
	}
	n := binary.BigEndian.Uint32(h[:])
	minimum := uint32(36)
	maximum := uint32(36 + MaxPayload)
	if outgoing {
		minimum++
		maximum = MaxFrame
	}
	if n < minimum || n > maximum {
		return Datagram{}, ErrFrame
	}
	b := make([]byte, int(n))
	if _, e := io.ReadFull(r, b); e != nil {
		if errors.Is(e, io.EOF) {
			e = io.ErrUnexpectedEOF
		}
		return Datagram{}, e
	}
	return DecodeUDP(b, outgoing)
}

type EchoRequest struct {
	ID          uint16
	Destination netip.Addr
	Sequence    uint16
	TTL         uint8
	DataSize    uint16
}
type EchoReply struct {
	ID         uint16
	Source     netip.Addr
	Type, Code uint8
	Sequence   uint16
}

func EncodeEchoRequest(v EchoRequest) ([]byte, error) {
	if !v.Destination.IsValid() || v.Destination.IsUnspecified() || v.Destination.IsMulticast() || v.TTL == 0 || v.DataSize > MaxPayload {
		return nil, ErrFrame
	}
	b := make([]byte, 23)
	binary.BigEndian.PutUint16(b, v.ID)
	if PutIP(b[2:18], v.Destination) != nil {
		return nil, ErrFrame
	}
	binary.BigEndian.PutUint16(b[18:], v.Sequence)
	b[20] = v.TTL
	binary.BigEndian.PutUint16(b[21:], v.DataSize)
	return b, nil
}
func DecodeEchoRequest(b []byte) (EchoRequest, error) {
	var v EchoRequest
	if len(b) != 23 {
		return v, ErrFrame
	}
	ip, e := IP(b[2:18])
	if e != nil {
		return v, e
	}
	v = EchoRequest{binary.BigEndian.Uint16(b), ip, binary.BigEndian.Uint16(b[18:]), b[20], binary.BigEndian.Uint16(b[21:])}
	if _, e = EncodeEchoRequest(v); e != nil {
		return EchoRequest{}, e
	}
	return v, nil
}
func EncodeEchoReply(v EchoReply) ([]byte, error) {
	if !v.Source.IsValid() || v.Source.IsUnspecified() || v.Source.IsMulticast() {
		return nil, ErrFrame
	}
	b := make([]byte, 22)
	binary.BigEndian.PutUint16(b, v.ID)
	if PutIP(b[2:18], v.Source) != nil {
		return nil, ErrFrame
	}
	b[18] = v.Type
	b[19] = v.Code
	binary.BigEndian.PutUint16(b[20:], v.Sequence)
	return b, nil
}
func DecodeEchoReply(b []byte) (EchoReply, error) {
	var v EchoReply
	if len(b) != 22 {
		return v, ErrFrame
	}
	ip, e := IP(b[2:18])
	if e != nil {
		return v, e
	}
	v = EchoReply{binary.BigEndian.Uint16(b), ip, b[18], b[19], binary.BigEndian.Uint16(b[20:])}
	if _, e = EncodeEchoReply(v); e != nil {
		return EchoReply{}, e
	}
	return v, nil
}
