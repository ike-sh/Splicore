// Package mkcp implements an independent reliable stream over modern mKCP UDP
// framing. Account authentication and proxy protocol framing belong to callers.
package mkcp

import (
	"encoding/binary"
	"errors"
)

const (
	ackCode byte = iota
	dataCode
	endCode
	helloCode
	dataHeader = 18
)

var errPacket = errors.New("invalid modern mKCP datagram")

// record is a neutral decoded wire event, not a retransmission queue object.
type record struct {
	token                                        uint16
	code                                         byte
	closing                                      bool
	stamp, sequence, floor, edge, next, interval uint32
	numbers                                      []uint32
	data                                         []byte
}

func earlier(a, b uint32) bool           { return int32(a-b) < 0 }
func within(n, start, count uint32) bool { return n-start < count }

// decode validates the complete datagram before any session state is changed.
// Borrowed payload slices are copied only when admitted to bounded storage.
func decode(b []byte, mtu int) ([]record, error) {
	if len(b) < 4 || len(b) > mtu {
		return nil, errPacket
	}
	var out []record
	var token uint16
	for len(b) > 0 {
		if len(b) < 4 || len(out) >= mtu/16 {
			return nil, errPacket
		}
		r := record{token: binary.BigEndian.Uint16(b), code: b[2], closing: b[3] == 1}
		if b[3] > 1 || len(out) > 0 && r.token != token {
			return nil, errPacket
		}
		token = r.token
		n := 0
		switch r.code {
		case dataCode:
			if len(b) < dataHeader {
				return nil, errPacket
			}
			size := int(binary.BigEndian.Uint16(b[16:18]))
			n = dataHeader + size
			if size == 0 || n > len(b) {
				return nil, errPacket
			}
			r.stamp = binary.BigEndian.Uint32(b[4:8])
			r.sequence = binary.BigEndian.Uint32(b[8:12])
			r.floor = binary.BigEndian.Uint32(b[12:16])
			if earlier(r.sequence, r.floor) {
				return nil, errPacket
			}
			r.data = b[dataHeader:n]
		case ackCode:
			if len(b) < 17 {
				return nil, errPacket
			}
			count := int(b[16])
			n = 17 + 4*count
			if n > len(b) {
				return nil, errPacket
			}
			r.edge = binary.BigEndian.Uint32(b[4:8])
			r.next = binary.BigEndian.Uint32(b[8:12])
			r.stamp = binary.BigEndian.Uint32(b[12:16])
			r.numbers = make([]uint32, count)
			for i := range r.numbers {
				r.numbers[i] = binary.BigEndian.Uint32(b[17+i*4:])
			}
		case endCode, helloCode:
			if len(b) < 16 {
				return nil, errPacket
			}
			n = 16
			r.floor = binary.BigEndian.Uint32(b[4:8])
			r.next = binary.BigEndian.Uint32(b[8:12])
			r.interval = binary.BigEndian.Uint32(b[12:16])
		default:
			return nil, errPacket
		}
		out = append(out, r)
		b = b[n:]
	}
	return out, nil
}

func encode(r record) []byte {
	n := 16
	if r.code == dataCode {
		n = dataHeader + len(r.data)
	}
	if r.code == ackCode {
		n = 17 + 4*len(r.numbers)
	}
	b := make([]byte, n)
	binary.BigEndian.PutUint16(b, r.token)
	b[2] = r.code
	if r.closing {
		b[3] = 1
	}
	put := func(offset int, v uint32) { binary.BigEndian.PutUint32(b[offset:offset+4], v) }
	switch r.code {
	case dataCode:
		put(4, r.stamp)
		put(8, r.sequence)
		put(12, r.floor)
		binary.BigEndian.PutUint16(b[16:18], uint16(len(r.data)))
		copy(b[18:], r.data)
	case ackCode:
		put(4, r.edge)
		put(8, r.next)
		put(12, r.stamp)
		b[16] = byte(len(r.numbers))
		for i, v := range r.numbers {
			put(17+4*i, v)
		}
	default:
		put(4, r.floor)
		put(8, r.next)
		put(12, r.interval)
	}
	return b
}
