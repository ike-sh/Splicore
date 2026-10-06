package wire

import (
	"encoding/binary"
	"net/netip"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

type Request struct {
	Command     byte
	ClientID    string
	Destination access.Endpoint
}

func canonicalHost(host string) string {
	if ip, e := netip.ParseAddr(host); e == nil {
		return ip.Unmap().String()
	}
	return host
}

func EncodeRequest(q Request) ([]byte, error) {
	if len(q.ClientID) > 255 {
		return nil, ErrFrame
	}
	p := append([]byte{1, q.Command, byte(len(q.ClientID))}, q.ClientID...)
	switch q.Command {
	case 0, 6:
		return p, nil
	case 1, 5:
		q.Destination.Host = canonicalHost(q.Destination.Host)
		if q.Destination.Validate() != nil || len(q.Destination.Host) > 255 {
			return nil, ErrFrame
		}
		p = append(p, byte(len(q.Destination.Host)))
		p = append(p, q.Destination.Host...)
		return binary.BigEndian.AppendUint16(p, q.Destination.Port), nil
	default:
		return nil, ErrFrame
	}
}
func DecodeRequest(p []byte, version int) (Request, []byte, error) {
	if len(p) < 3 || p[0] != 1 {
		return Request{}, nil, ErrFrame
	}
	q := Request{Command: p[1]}
	if q.Command == 0 && version == 6 {
		return q, nil, nil
	}
	idlen := int(p[2])
	p = p[3:]
	if len(p) < idlen {
		return q, nil, ErrFrame
	}
	q.ClientID = string(p[:idlen])
	p = p[idlen:]
	switch q.Command {
	case 0, 6:
		return q, p, nil
	case 1, 5:
		if len(p) < 1 || len(p) < 1+int(p[0])+2 {
			return q, nil, ErrFrame
		}
		n := int(p[0])
		q.Destination = access.Endpoint{Host: canonicalHost(string(p[1 : 1+n])), Port: binary.BigEndian.Uint16(p[1+n : 3+n])}
		if q.Destination.Validate() != nil {
			return q, nil, ErrFrame
		}
		return q, p[3+n:], nil
	default:
		return q, nil, ErrFrame
	}
}
func EncodeDatagram(dst access.Endpoint, payload []byte, response bool) ([]byte, error) {
	if dst.Validate() != nil {
		return nil, ErrFrame
	}
	ip, e := netip.ParseAddr(dst.Host)
	p := make([]byte, 0, len(payload)+260)
	if !response {
		p = append(p, 1)
	}
	if e == nil {
		ip = ip.Unmap()
		if !response {
			p = append(p, 0)
		}
		if ip.Is4() {
			p = append(p, 4)
		} else {
			p = append(p, 6)
		}
		p = append(p, ip.AsSlice()...)
	} else {
		if response || len(dst.Host) > 255 {
			return nil, ErrFrame
		}
		p = append(p, byte(len(dst.Host)))
		p = append(p, dst.Host...)
	}
	p = binary.BigEndian.AppendUint16(p, dst.Port)
	if len(p)+len(payload) > 65535 {
		return nil, ErrFrame
	}
	return append(p, payload...), nil
}
func DecodeDatagram(p []byte, response bool) (access.Endpoint, []byte, error) {
	if !response {
		if len(p) < 2 || p[0] != 1 {
			return access.Endpoint{}, nil, ErrFrame
		}
		p = p[1:]
	}
	if len(p) < 1 {
		return access.Endpoint{}, nil, ErrFrame
	}
	var host string
	if !response && p[0] != 0 {
		n := int(p[0])
		if len(p) < 1+n+2 {
			return access.Endpoint{}, nil, ErrFrame
		}
		host = string(p[1 : 1+n])
		p = p[1+n:]
	} else {
		if !response {
			p = p[1:]
		}
		if len(p) < 1 {
			return access.Endpoint{}, nil, ErrFrame
		}
		n := 0
		switch p[0] {
		case 4:
			n = 4
		case 6:
			n = 16
		default:
			return access.Endpoint{}, nil, ErrFrame
		}
		if len(p) < 1+n+2 {
			return access.Endpoint{}, nil, ErrFrame
		}
		ip, ok := netip.AddrFromSlice(p[1 : 1+n])
		if !ok {
			return access.Endpoint{}, nil, ErrFrame
		}
		host = ip.Unmap().String()
		p = p[1+n:]
	}
	if len(p) < 2 {
		return access.Endpoint{}, nil, ErrFrame
	}
	dst := access.Endpoint{Host: canonicalHost(host), Port: binary.BigEndian.Uint16(p[:2])}
	if dst.Validate() != nil {
		return access.Endpoint{}, nil, ErrFrame
	}
	return dst, p[2:], nil
}

func tunnelReply(p []byte) ([]byte, error) {
	if len(p) == 0 {
		return nil, ErrFrame
	}
	if p[0] == 0 {
		return p[1:], nil
	}
	if p[0] == 2 && len(p) >= 3 && len(p) == 3+int(p[2]) {
		return nil, ErrAuthentication
	}
	return nil, ErrFrame
}
