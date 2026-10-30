//go:build linux

package amneziawgendpoint

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/mdlayher/genetlink"
	NL "github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	awgFamily      = "amneziawg"
	awgGenlVersion = 3
)

// Checking sysfs first prevents generic netlink or rtnetlink from autoloading
// a module. Only an already loaded AWG module may receive a feature probe.
func loadedModule(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := os.Stat("/sys/module/amneziawg")
	if err != nil {
		return kernelError("already loaded AWG module", KernelUnavailable, err)
	}
	return nil
}

type genlConnection interface {
	SetDeadline(time.Time) error
	Execute(genetlink.Message, uint16, NL.HeaderFlags) ([]genetlink.Message, error)
	Close() error
}
type nativeControl struct {
	conn   genlConnection
	family genetlink.Family
}

func newNativeControl() (*nativeControl, error) {
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (*nativeControl, error) {
		return nil, errors.Join(e, cleanupError("AWG control open rollback", conn.Close()))
	}
	if err = conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return fail(err)
	}
	family, err := conn.GetFamily(awgFamily)
	if err != nil {
		return fail(err)
	}
	if family.Version != awgGenlVersion {
		return fail(&BackendError{Class: KernelUnavailable, Operation: "AWG generic netlink version 3 required"})
	}
	return &nativeControl{conn, family}, nil
}
func (c *nativeControl) Close() error { return c.conn.Close() }
func (c *nativeControl) execute(command uint8, attrs []byte, flags NL.HeaderFlags) ([]genetlink.Message, error) {
	if err := c.conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return nil, err
	}
	return c.conn.Execute(genetlink.Message{Header: genetlink.Header{Command: command, Version: awgGenlVersion}, Data: attrs}, c.family.ID, NL.Request|flags)
}
func attrBytes(typ uint16, b []byte) NL.Attribute  { return NL.Attribute{Type: typ, Data: b} }
func attrString(typ uint16, s string) NL.Attribute { return attrBytes(typ, append([]byte(s), 0)) }
func attr16(typ uint16, n uint16) NL.Attribute {
	return attrBytes(typ, binary.NativeEndian.AppendUint16(nil, n))
}

func attr32(typ uint16, n uint32) NL.Attribute {
	return attrBytes(typ, binary.NativeEndian.AppendUint32(nil, n))
}

func attr64(typ uint16, n uint64) NL.Attribute {
	return attrBytes(typ, binary.NativeEndian.AppendUint64(nil, n))
}

func boolByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

// Attribute IDs and layouts are pinned to the official kernel v3 UAPI.
// H ranges: native u64 hi<<32|lo. Small ranges: native u32 hi<<16|lo.
func obfuscationAttrs(c E.AmneziaWG, includeZeroKey bool) []NL.Attribute {
	attrs := []NL.Attribute{attr16(9, c.Jc), attr16(10, c.Jmin), attr16(11, c.Jmax), attr16(12, c.S1), attr16(13, c.S2), attr16(19, c.S3), attr16(20, c.S4)}
	for i, h := range c.Headers() {
		attrs = append(attrs, attr64(uint16(14+i), uint64(h.Max)<<32|uint64(h.Min)))
	}
	for i, s := range c.Signatures() {
		if s != "" {
			attrs = append(attrs, attrString(uint16(21+i), nativeCPS(s)))
		}
	}
	key := c.HeaderProtectionKey.Reveal()
	if includeZeroKey || key != ([32]byte{}) {
		attrs = append(attrs, attrBytes(26, key[:]))
	}
	for i, r := range []E.AWGRange{c.ContentPaddingAddition, c.RekeyAfterTime, c.RekeyTimeout, c.RejectAfterTime, c.KeepaliveTimeout, c.MaxHandshakeAttempts} {
		attrs = append(attrs, attr32(uint16(27+i), r.Max<<16|r.Min))
	}
	return append(attrs, attrBytes(33, []byte{boolByte(c.RandomTrailers)}), attrBytes(34, []byte{boolByte(c.DisableCookies)}))
}

// The kernel parser requires 0x and a single separating space. Convert the
// validated AST without changing I-packet bytes. d/ds receive an empty source;
// dz emits zero bytes. The official kernel skips an empty signature packet.
func nativeCPS(spec string) string {
	cps, _ := E.ParseCPS(spec)
	var b strings.Builder
	for _, tag := range cps.Tags {
		switch tag.Kind {
		case "b":
			fmt.Fprintf(&b, "<b 0x%s>", hex.EncodeToString(tag.Data))
		case "t":
			b.WriteString("<t>")
		case "r", "rc", "rd":
			fmt.Fprintf(&b, "<%s %d>", tag.Kind, tag.Length)
		case "dz":
			if tag.Length > 0 {
				fmt.Fprintf(&b, "<b 0x%s>", strings.Repeat("00", tag.Length))
			}
		}
	}
	if b.Len() == 0 && spec != "" {
		return "<r 0>"
	}
	return b.String()
}

func encodeDevice(name string, c E.AmneziaWG, cfg wgtypes.Config) ([]byte, error) {
	key := c.PrivateKey.Reveal()
	attrs := []NL.Attribute{attrString(2, name), attrBytes(3, key[:]), attr32(5, 1), attr16(6, uint16(*cfg.ListenPort)), attr32(7, uint32(*cfg.FirewallMark))}
	attrs = append(attrs, obfuscationAttrs(c, false)...)
	return NL.MarshalAttributes(attrs)
}

func sockaddr(ap netip.AddrPort) []byte {
	ip := ap.Addr()
	if ip.Is4() {
		b := make([]byte, 16)
		binary.NativeEndian.PutUint16(b, unix.AF_INET)
		binary.BigEndian.PutUint16(b[2:], ap.Port())
		v := ip.As4()
		copy(b[4:], v[:])
		return b
	}
	b := make([]byte, 28)
	binary.NativeEndian.PutUint16(b, unix.AF_INET6)
	binary.BigEndian.PutUint16(b[2:], ap.Port())
	v := ip.As16()
	copy(b[8:], v[:])
	return b
}

func decodeSockaddr(b []byte) (*net.UDPAddr, error) {
	if len(b) < 2 {
		return nil, ErrNativeAttributes
	}
	switch binary.NativeEndian.Uint16(b) {
	case unix.AF_INET:
		if len(b) != 16 {
			return nil, ErrNativeAttributes
		}
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[4:8])), binary.BigEndian.Uint16(b[2:4]))), nil
	case unix.AF_INET6:
		if len(b) != 28 || binary.NativeEndian.Uint32(b[24:]) != 0 {
			return nil, ErrNativeAttributes
		}
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[8:24])), binary.BigEndian.Uint16(b[2:4]))), nil
	}
	return nil, ErrNativeAttributes
}

func encodePeer(name string, p wgtypes.PeerConfig, first bool, allowed []net.IPNet) ([]byte, error) {
	attrs := []NL.Attribute{attrBytes(1, p.PublicKey[:])}
	if first {
		attrs = append(attrs, attr32(3, 2))
		if p.PresharedKey != nil {
			attrs = append(attrs, attrBytes(2, p.PresharedKey[:]))
		}
		if p.Endpoint != nil {
			attrs = append(attrs, attrBytes(4, sockaddr(p.Endpoint.AddrPort())))
		}
		n := uint32(*p.PersistentKeepaliveInterval / time.Second)
		attrs = append(attrs, attr32(5, n<<16|n))
	}
	ips := make([]NL.Attribute, 0, len(allowed))
	for _, ip := range allowed {
		ones, _ := ip.Mask.Size()
		ap, ok := netip.AddrFromSlice(ip.IP)
		if !ok {
			return nil, ErrNativeAttributes
		}
		ap = ap.Unmap()
		family := uint16(unix.AF_INET6)
		if ap.Is4() {
			family = unix.AF_INET
		}
		b, err := NL.MarshalAttributes([]NL.Attribute{attr16(1, family), attrBytes(2, ap.AsSlice()), attrBytes(3, []byte{byte(ones)})})
		if err != nil {
			return nil, err
		}
		ips = append(ips, attrBytes(uint16(len(ips))|NL.Nested, b))
	}
	raw, err := NL.MarshalAttributes(ips)
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, attrBytes(9|NL.Nested, raw))
	raw, err = NL.MarshalAttributes(attrs)
	if err != nil {
		return nil, err
	}
	raw, err = NL.MarshalAttributes([]NL.Attribute{attrBytes(NL.Nested, raw)})
	if err != nil {
		return nil, err
	}
	return NL.MarshalAttributes([]NL.Attribute{attrString(2, name), attrBytes(8|NL.Nested, raw)})
}

func (c *nativeControl) set(name string, attrs []NL.Attribute) error {
	raw, err := NL.MarshalAttributes(append([]NL.Attribute{attrString(2, name)}, attrs...))
	if err != nil {
		return err
	}
	_, err = c.execute(1, raw, NL.Acknowledge)
	return err
}

func (c *nativeControl) probe(name string) error {
	// Temporary feature configuration on our exclusively owned DOWN link, with
	// no peers or traffic. Never probes an existing foreign device.
	p := E.AmneziaWG{S1: 12, S2: 12, S3: 12, S4: 12, ContentPaddingAddition: E.AWGRange{Min: 1, Max: 3}, RandomTrailers: true, DisableCookies: true, RekeyAfterTime: E.AWGRange{Min: 20, Max: 21}, RekeyTimeout: E.AWGRange{Min: 2, Max: 3}, RejectAfterTime: E.AWGRange{Min: 40, Max: 41}, KeepaliveTimeout: E.AWGRange{Min: 4, Max: 5}, MaxHandshakeAttempts: E.AWGRange{Min: 6, Max: 7}, I1: "<b 0102>"}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return err
	}
	p.HeaderProtectionKey, _ = E.ParseSecret(E.EncodeKey(key))
	if err := c.set(name, obfuscationAttrs(p, false)); err != nil {
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP) {
			return &BackendError{Class: KernelUnavailable, Operation: "AWG 3.1 feature probe rejected", Cause: err}
		}
		return err
	}
	_, actual, err := c.read(name)
	if err != nil {
		return err
	}
	if err = verifyObfuscation(actual, p); err != nil {
		return &BackendError{Class: KernelUnavailable, Operation: "AWG 3.1 feature readback", Cause: ErrNativeAttributes}
	}
	return nil
}

func (c *nativeControl) configure(name string, config E.AmneziaWG, cfg wgtypes.Config) error {
	b, err := encodeDevice(name, config, cfg)
	if err != nil {
		return err
	}
	if _, err = c.execute(1, b, NL.Acknowledge); err != nil {
		return err
	}
	for _, p := range cfg.Peers {
		// Small bounded messages support the complete peer/AllowedIPs limits.
		for i := 0; i < len(p.AllowedIPs); i += 64 {
			end := min(i+64, len(p.AllowedIPs))
			b, err = encodePeer(name, p, i == 0, p.AllowedIPs[i:end])
			if err != nil {
				return err
			}
			if _, err = c.execute(1, b, NL.Acknowledge); err != nil {
				return err
			}
		}
	}
	_, attrs, err := c.read(name)
	if err != nil {
		return err
	}
	return verifyObfuscation(attrs, config)
}

var ErrNativeAttributes = errors.New("invalid AWG native attributes")

func attrsMap(data []byte) (map[uint16][]byte, error) {
	if len(data) > 65536 {
		return nil, ErrNativeAttributes
	}
	attrs, err := NL.UnmarshalAttributes(data)
	if err != nil {
		return nil, ErrNativeAttributes
	}
	result := make(map[uint16][]byte, len(attrs))
	for _, a := range attrs {
		typ := a.Type & 0x3fff
		if _, ok := result[typ]; ok {
			return nil, ErrNativeAttributes
		}
		result[typ] = a.Data
	}
	return result, nil
}

func verifyObfuscation(actual map[uint16][]byte, want E.AmneziaWG) error {
	for _, a := range obfuscationAttrs(want, false) {
		if !bytes.Equal(actual[a.Type], a.Data) {
			return &BackendError{Class: RuntimeFailure, Operation: "AWG attribute readback invariant"}
		}
	}
	// A disabled key may be omitted; a stale nonzero probe key is fatal.
	if want.HeaderProtectionKey.Reveal() == ([32]byte{}) {
		if b := actual[26]; len(b) != 0 && !bytes.Equal(b, make([]byte, 32)) {
			return ErrNativeAttributes
		}
	}
	return nil
}

func (c *nativeControl) Device(name string) (*wgtypes.Device, error) {
	d, _, err := c.read(name)
	return d, err
}

func (c *nativeControl) read(name string) (*wgtypes.Device, map[uint16][]byte, error) {
	raw, err := NL.MarshalAttributes([]NL.Attribute{attrString(2, name)})
	if err != nil {
		return nil, nil, err
	}
	messages, err := c.execute(0, raw, NL.Dump)
	if err != nil {
		return nil, nil, err
	}
	d := &wgtypes.Device{Name: name}
	all := map[uint16][]byte{}
	peers := map[wgtypes.Key]int{}
	for _, m := range messages {
		if m.Header.Version != awgGenlVersion {
			return nil, nil, ErrNativeAttributes
		}
		attrs, err := attrsMap(m.Data)
		if err != nil {
			return nil, nil, err
		}
		for k, v := range attrs {
			if k != 8 {
				if old, ok := all[k]; ok && !bytes.Equal(old, v) {
					return nil, nil, ErrNativeAttributes
				}
				all[k] = v
			}
		}
		if data, ok := attrs[8]; ok {
			nested, err := NL.UnmarshalAttributes(data)
			if err != nil {
				return nil, nil, ErrNativeAttributes
			}
			if len(nested) > 128 {
				return nil, nil, ErrNativeAttributes
			}
			for _, a := range nested {
				p, err := decodePeer(a.Data)
				if err != nil {
					return nil, nil, err
				}
				if i, ok := peers[p.PublicKey]; ok {
					d.Peers[i].AllowedIPs = append(d.Peers[i].AllowedIPs, p.AllowedIPs...)
					if len(d.Peers[i].AllowedIPs) > 256 {
						return nil, nil, ErrNativeAttributes
					}
				} else {
					if len(d.Peers) >= 128 {
						return nil, nil, ErrNativeAttributes
					}
					peers[p.PublicKey] = len(d.Peers)
					d.Peers = append(d.Peers, p)
				}
			}
		}
	}
	for k, n := range map[uint16]int{3: 32, 4: 32, 6: 2, 7: 4} {
		if b, ok := all[k]; ok && len(b) != n {
			return nil, nil, ErrNativeAttributes
		}
	}
	if b := all[3]; len(b) == 32 {
		copy(d.PrivateKey[:], b)
	}
	if b := all[4]; len(b) == 32 {
		copy(d.PublicKey[:], b)
	}
	if b := all[6]; len(b) == 2 {
		d.ListenPort = int(binary.NativeEndian.Uint16(b))
	}
	if b := all[7]; len(b) == 4 {
		d.FirewallMark = int(binary.NativeEndian.Uint32(b))
	}
	return d, all, nil
}

func decodePeer(data []byte) (wgtypes.Peer, error) {
	var p wgtypes.Peer
	a, err := attrsMap(data)
	if err != nil {
		return p, err
	}
	if len(a[1]) != 32 {
		return p, ErrNativeAttributes
	}
	copy(p.PublicKey[:], a[1])
	for k, n := range map[uint16]int{2: 32, 5: 4, 6: 16, 7: 8, 8: 8} {
		if b, ok := a[k]; ok && len(b) != n {
			return p, ErrNativeAttributes
		}
	}
	if b := a[2]; b != nil {
		copy(p.PresharedKey[:], b)
	}
	if b := a[4]; b != nil {
		p.Endpoint, err = decodeSockaddr(b)
		if err != nil {
			return p, err
		}
	}
	if b := a[5]; b != nil {
		v := binary.NativeEndian.Uint32(b)
		if uint16(v) != uint16(v>>16) {
			return p, ErrNativeAttributes
		}
		p.PersistentKeepaliveInterval = time.Duration(uint16(v)) * time.Second
	}
	if b := a[6]; b != nil {
		sec, nsec := int64(binary.NativeEndian.Uint64(b)), int64(binary.NativeEndian.Uint64(b[8:]))
		if nsec < 0 || nsec >= 1e9 {
			return p, ErrNativeAttributes
		}
		if sec != 0 {
			p.LastHandshakeTime = time.Unix(sec, nsec)
		}
	}
	if b := a[7]; b != nil {
		p.ReceiveBytes = int64(binary.NativeEndian.Uint64(b))
	}
	if b := a[8]; b != nil {
		p.TransmitBytes = int64(binary.NativeEndian.Uint64(b))
	}
	if b := a[9]; b != nil {
		ips, err := NL.UnmarshalAttributes(b)
		if err != nil || len(ips) > 256 {
			return p, ErrNativeAttributes
		}
		for _, ip := range ips {
			v, err := attrsMap(ip.Data)
			if err != nil || len(v[1]) != 2 || len(v[3]) != 1 {
				return p, ErrNativeAttributes
			}
			family := binary.NativeEndian.Uint16(v[1])
			bits := 128
			if family == unix.AF_INET {
				bits = 32
			} else if family != unix.AF_INET6 {
				return p, ErrNativeAttributes
			}
			if len(v[2]) != bits/8 || int(v[3][0]) > bits {
				return p, ErrNativeAttributes
			}
			p.AllowedIPs = append(p.AllowedIPs, net.IPNet{IP: append(net.IP(nil), v[2]...), Mask: net.CIDRMask(int(v[3][0]), bits)})
		}
	}
	return p, nil
}
