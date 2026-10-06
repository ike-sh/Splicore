// Package address owns bounded wire address codecs over access.Endpoint.
// SOCKS and Shadowsocks share this address representation; other protocols keep
// their own wire tags. Returned bytes belong exclusively to the caller.
package address

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

var ErrAddress = errors.New("invalid wire address")

// Wire addresses also describe wildcard SOCKS bind endpoints with port zero.
func valid(e access.Endpoint) bool {
	if e.Port == 0 {
		e.Port = 1
	}
	return e.Validate() == nil
}

func MarshalSOCKS(e access.Endpoint) ([]byte, error) {
	if !valid(e) {
		return nil, ErrAddress
	}
	var b []byte
	if ip, err := netip.ParseAddr(e.Host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			v := ip.As4()
			b = append([]byte{1}, v[:]...)
		} else {
			v := ip.As16()
			b = append([]byte{4}, v[:]...)
		}
	} else {
		b = append([]byte{3, byte(len(e.Host))}, e.Host...)
	}
	return binary.BigEndian.AppendUint16(b, e.Port), nil
}

func ReadSOCKS(r io.Reader) (access.Endpoint, error) {
	var tag [1]byte
	if _, err := io.ReadFull(r, tag[:]); err != nil {
		return access.Endpoint{}, ErrAddress
	}
	var host string
	switch tag[0] {
	case 1:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return access.Endpoint{}, ErrAddress
		}
		host = netip.AddrFrom4(b).String()
	case 4:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return access.Endpoint{}, ErrAddress
		}
		host = netip.AddrFrom16(b).Unmap().String()
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(r, size[:]); err != nil || size[0] == 0 {
			return access.Endpoint{}, ErrAddress
		}
		b := make([]byte, int(size[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return access.Endpoint{}, ErrAddress
		}
		host = string(b)
		if ip, err := netip.ParseAddr(host); err == nil {
			host = ip.Unmap().String()
		}
	default:
		return access.Endpoint{}, ErrAddress
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return access.Endpoint{}, ErrAddress
	}
	e := access.Endpoint{Host: host, Port: binary.BigEndian.Uint16(port[:])}
	if !valid(e) {
		return access.Endpoint{}, ErrAddress
	}
	return e, nil
}
