package wire

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"golang.org/x/crypto/chacha20poly1305"
)

// Datagram owns Payload after Decode. No backing array is reused by the caller.
type Datagram struct {
	User                           int
	Session, Packet, ClientSession uint64
	Destination                    access.Endpoint
	Payload                        []byte
}

func SessionID() (uint64, error) {
	b, e := random(8)
	if e != nil {
		return 0, e
	}
	return binary.BigEndian.Uint64(b), nil
}
func EncodePacket(keys []*Key, p Datagram, response bool, now time.Time) ([]byte, error) {
	if len(keys) == 0 || len(p.Payload) > MaxDatagram {
		return nil, ErrFrame
	}
	k := keys[len(keys)-1]
	address, e := Address(p.Destination)
	if e != nil {
		return nil, e
	}
	if k.Method.Edition == "2017" {
		salt, e := random(k.Method.KeySize)
		if e != nil {
			return nil, e
		}
		aead, e := k.aead(salt)
		if e != nil {
			return nil, e
		}
		plain := append(address, p.Payload...)
		if len(salt)+len(plain)+16 > MaxDatagram {
			return nil, ErrFrame
		}
		return append(salt, aead.Seal(nil, make([]byte, 12), plain, nil)...), nil
	}
	separate := make([]byte, 16)
	binary.BigEndian.PutUint64(separate, p.Session)
	binary.BigEndian.PutUint64(separate[8:], p.Packet)
	main := make([]byte, 9)
	if response {
		main[0] = 1
	}
	putTime(main[1:9], now)
	if response {
		main = binary.BigEndian.AppendUint64(main, p.ClientSession)
	}
	// DNS-like packets may be padded using a CSPRNG. All other payloads use the
	// canonical permitted zero-padding policy to preserve practical UDP sizes.
	var padding []byte
	if p.Destination.Port == 53 && len(p.Payload) < 512 {
		padding, e = randomPadding()
		if e != nil {
			return nil, e
		}
	}
	main = binary.BigEndian.AppendUint16(main, uint16(len(padding)))
	main = append(main, padding...)
	main = append(main, address...)
	main = append(main, p.Payload...)
	if k.Method.Name == "2022-blake3-chacha20-poly1305" {
		nonce, e := random(24)
		if e != nil {
			return nil, e
		}
		aead, e := chacha20poly1305.NewX(k.Material)
		if e != nil {
			return nil, e
		}
		plain := append(separate, main...)
		if len(nonce)+len(plain)+16 > MaxDatagram {
			return nil, ErrFrame
		}
		return append(nonce, aead.Seal(nil, nonce, plain, nil)...), nil
	}
	aead, e := k.aead(separate[:8])
	if e != nil {
		return nil, e
	}
	ciphertext := aead.Seal(nil, separate[4:16], main, nil)
	head := make([]byte, 16)
	first := keys[0]
	if response {
		first = k
	}
	block, e := first.block()
	if e != nil {
		return nil, e
	}
	block.Encrypt(head, separate)
	if !response {
		for n := 0; n < len(keys)-1; n++ {
			block, e := keys[n].block()
			if e != nil {
				return nil, e
			}
			plain := make([]byte, 16)
			for i := range plain {
				plain[i] = keys[n+1].Hash[i] ^ separate[i]
			}
			identity := make([]byte, 16)
			block.Encrypt(identity, plain)
			head = append(head, identity...)
		}
	}
	if len(head)+len(ciphertext) > MaxDatagram {
		return nil, ErrFrame
	}
	return append(head, ciphertext...), nil
}
func DecodePacket(users []*Key, identity *Key, body []byte, response bool, expectedClient uint64, replay *SaltCache, now time.Time) (Datagram, error) {
	var out Datagram
	if len(users) == 0 || len(body) > MaxDatagram {
		return out, ErrFrame
	}
	m := users[0].Method
	var plain, separate []byte
	selected := -1
	if m.Edition == "2017" {
		if len(body) < m.KeySize+16 {
			return out, ErrFrame
		}
		salt := body[:m.KeySize]
		for n, k := range users {
			a, e := k.aead(salt)
			if e != nil {
				return out, e
			}
			p, e := a.Open(nil, make([]byte, 12), body[m.KeySize:], nil)
			if e == nil {
				plain = p
				selected = n
				break
			}
		}
		if selected < 0 {
			return out, ErrAuth
		}
		dst, payload, e := splitAddress(plain)
		if e != nil {
			return out, e
		}
		if e = replay.Check(users[selected], salt, now); e != nil {
			return out, e
		}
		return Datagram{User: selected, Destination: dst, Payload: payload}, nil
	}
	if m.Name == "2022-blake3-chacha20-poly1305" {
		if len(users) != 1 || identity != nil || len(body) < 24+16+16+11 {
			return out, ErrFrame
		}
		a, e := chacha20poly1305.NewX(users[0].Material)
		if e != nil {
			return out, e
		}
		p, e := a.Open(nil, body[:24], body[24:], nil)
		if e != nil {
			return out, ErrAuth
		}
		if len(p) < 16 {
			return out, ErrFrame
		}
		separate = p[:16]
		plain = p[16:]
		selected = 0
	} else {
		offset := 16
		if identity != nil {
			offset += 16
		}
		if len(body) < offset+16+11 {
			return out, ErrFrame
		}
		first := users[0]
		if identity != nil {
			first = identity
		}
		block, e := first.block()
		if e != nil {
			return out, e
		}
		separate = make([]byte, 16)
		block.Decrypt(separate, body[:16])
		if identity != nil {
			hash := make([]byte, 16)
			block.Decrypt(hash, body[16:32])
			for i := range hash {
				hash[i] ^= separate[i]
			}
			for n, k := range users {
				if subtle.ConstantTimeCompare(hash, k.Hash[:]) == 1 {
					selected = n
					break
				}
			}
			if selected < 0 {
				return out, ErrAuth
			}
		} else if len(users) == 1 {
			selected = 0
		} else {
			return out, ErrAuth
		}
		a, e := users[selected].aead(separate[:8])
		if e != nil {
			return out, e
		}
		plain, e = a.Open(nil, separate[4:16], body[offset:], nil)
		if e != nil {
			return out, ErrAuth
		}
	}
	out.User = selected
	out.Session = binary.BigEndian.Uint64(separate[:8])
	out.Packet = binary.BigEndian.Uint64(separate[8:])
	if len(plain) < 11 {
		return out, ErrFrame
	}
	kind := byte(0)
	if response {
		kind = 1
	}
	if plain[0] != kind {
		return out, ErrFrame
	}
	if !timestampOK(binary.BigEndian.Uint64(plain[1:9]), now) {
		return out, ErrTimestamp
	}
	plain = plain[9:]
	if response {
		if len(plain) < 10 {
			return out, ErrFrame
		}
		out.ClientSession = binary.BigEndian.Uint64(plain[:8])
		if out.ClientSession != expectedClient {
			return out, ErrAuth
		}
		plain = plain[8:]
	}
	if len(plain) < 2 {
		return out, ErrFrame
	}
	padding := int(binary.BigEndian.Uint16(plain[:2]))
	plain = plain[2:]
	if padding > len(plain) {
		return out, ErrFrame
	}
	plain = plain[padding:]
	dst, payload, e := splitAddress(plain)
	if e != nil {
		return out, e
	}
	out.Destination = dst
	out.Payload = bytes.Clone(payload)
	return out, nil
}
