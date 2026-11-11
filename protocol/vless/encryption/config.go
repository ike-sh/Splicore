// Package encryption implements the VLESS encrypted stream protocol. It owns no
// sockets, DNS, routes, accounts, or transport security.
package encryption

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	ErrConfig    = errors.New("invalid VLESS encryption configuration")
	ErrHandshake = errors.New("VLESS encryption handshake rejected")
	ErrRecord    = errors.New("invalid VLESS encrypted record")
	ErrResume    = errors.New("VLESS encryption requires a fresh handshake")
)

const (
	method  = "mlkem768x25519plus"
	maxKeys = 8
)

type key struct {
	xPrivate   *ecdh.PrivateKey
	xPublic    *ecdh.PublicKey
	kemPrivate *mlkem.DecapsulationKey768
	kemPublic  *mlkem.EncapsulationKey768
	public     []byte
}
type tuple struct{ probability, low, high int }

// Config is immutable after parsing. Formatting never reveals key material.
type Config struct {
	mode     string
	resume   bool
	from, to int
	keys     []key
	padding  []tuple
	original string
	server   bool
}

func (*Config) Format(s fmt.State, _ rune)  { _, _ = s.Write([]byte("VLESSEncryption{[REDACTED]}")) }
func (c *Config) Mode() string              { return c.mode }
func ParseClient(s string) (*Config, error) { return parse(s, false) }
func ParseServer(s string) (*Config, error) { return parse(s, true) }
func parse(s string, server bool) (*Config, error) {
	if s == "none" {
		return nil, nil
	}
	if len(s) > 16384 {
		return nil, ErrConfig
	}
	parts := strings.Split(s, ".")
	if len(parts) < 4 || parts[0] != method {
		return nil, ErrConfig
	}
	c := &Config{mode: parts[1], server: server, original: s}
	if c.mode != "native" && c.mode != "xorpub" && c.mode != "random" {
		return nil, ErrConfig
	}
	if server {
		duration := strings.Split(strings.TrimSuffix(parts[2], "s"), "-")
		if len(duration) > 2 {
			return nil, ErrConfig
		}
		var err error
		c.from, err = strconv.Atoi(duration[0])
		if err != nil || c.from < 0 || c.from > 65535 {
			return nil, ErrConfig
		}
		if len(duration) == 2 {
			c.to, err = strconv.Atoi(duration[1])
			if err != nil || c.to < c.from || c.to > 65535 {
				return nil, ErrConfig
			}
		}
	} else {
		switch parts[2] {
		case "0rtt":
			c.resume = true
		case "1rtt":
		default:
			return nil, ErrConfig
		}
	}
	firstKey := 3
	for firstKey < len(parts) && len(parts[firstKey]) < 20 {
		firstKey++
	}
	if firstKey == len(parts) || len(parts)-firstKey > maxKeys || firstKey-3 > maxPaddingTuples {
		return nil, ErrConfig
	}
	total := 0
	for n, p := range parts[3:firstKey] {
		fields := strings.Split(p, "-")
		if len(fields) != 3 {
			return nil, ErrConfig
		}
		v := [3]int{}
		for j, f := range fields {
			i, e := strconv.Atoi(f)
			if e != nil || i < 0 || i > 65553 {
				return nil, ErrConfig
			}
			v[j] = i
		}
		if v[0] > 100 || v[1] > v[2] || n == 0 && (v[0] != 100 || v[1] < 35) {
			return nil, ErrConfig
		}
		if n%2 == 0 {
			total += v[2]
			if total > 65553 {
				return nil, ErrConfig
			}
		} else if v[2] > maxPaddingGapMS {
			return nil, ErrConfig
		}
		c.padding = append(c.padding, tuple{v[0], v[1], v[2]})
	}
	for _, p := range parts[firstKey:] {
		b, e := base64.RawURLEncoding.Strict().DecodeString(p)
		if e != nil || base64.RawURLEncoding.EncodeToString(b) != p {
			return nil, ErrConfig
		}
		k := key{}
		switch {
		case len(b) == 32 && server:
			k.xPrivate, e = ecdh.X25519().NewPrivateKey(b)
			if e == nil {
				k.xPublic = k.xPrivate.PublicKey()
			}
		case len(b) == 32:
			k.xPublic, e = ecdh.X25519().NewPublicKey(b)
			if e == nil {
				var probe *ecdh.PrivateKey
				probe, e = ecdh.X25519().NewPrivateKey(make([]byte, 32))
				if e == nil {
					_, e = probe.ECDH(k.xPublic)
				}
			}
		case len(b) == 64 && server:
			k.kemPrivate, e = mlkem.NewDecapsulationKey768(b)
			if e == nil {
				k.kemPublic = k.kemPrivate.EncapsulationKey()
			}
		case len(b) == 1184 && !server:
			k.kemPublic, e = mlkem.NewEncapsulationKey768(b)
		default:
			e = ErrConfig
		}
		clear(b)
		if e != nil {
			return nil, ErrConfig
		}
		if k.xPublic != nil {
			k.public = k.xPublic.Bytes()
		} else {
			k.public = k.kemPublic.Bytes()
		}
		c.keys = append(c.keys, k)
	}
	return c, nil
}

// ClientString projects only public authentication keys from a server config.
func (c *Config) ClientString(resume bool) string {
	policy := "1rtt"
	if resume {
		policy = "0rtt"
	}
	fields := []string{method, c.mode, policy}
	// Client padding is independently configured; preserve valid explicit tuples.
	for _, p := range c.padding {
		fields = append(fields, fmt.Sprintf("%d-%d-%d", p.probability, p.low, p.high))
	}
	for _, k := range c.keys {
		fields = append(fields, base64.RawURLEncoding.EncodeToString(k.public))
	}
	return strings.Join(fields, ".")
}

// Generate produces compatible independent server/client configuration strings.
// Its return values are explicit secret output for the stateless key utility.
func Generate(auth, mode, policy, duration, padding string) (string, string, error) {
	var private, public []byte
	switch auth {
	case "x25519":
		k, e := ecdh.X25519().GenerateKey(rand.Reader)
		if e != nil {
			return "", "", e
		}
		private = k.Bytes()
		public = k.PublicKey().Bytes()
	case "mlkem768":
		k, e := mlkem.GenerateKey768()
		if e != nil {
			return "", "", e
		}
		private = k.Bytes()
		public = k.EncapsulationKey().Bytes()
	default:
		return "", "", ErrConfig
	}
	defer clear(private)
	prefix := method + "." + mode + "."
	tail := "."
	if padding != "" {
		tail += "" + padding + "."
	}
	server := prefix + duration + tail + base64.RawURLEncoding.EncodeToString(private)
	client := prefix + policy + tail + base64.RawURLEncoding.EncodeToString(public)
	if _, e := ParseServer(server); e != nil {
		return "", "", e
	}
	if _, e := ParseClient(client); e != nil {
		return "", "", e
	}
	return server, client, nil
}
