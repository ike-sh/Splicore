package streamtransport

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
)

// HysteriaObfs is UDP intent below QUIC; it is never a protocol credential.
type HysteriaObfs struct {
	Type          string `json:"type"`
	Password      string `json:"password,omitempty"`
	MinPacketSize int    `json:"min_packet_size,omitempty"`
	MaxPacketSize int    `json:"max_packet_size,omitempty"`
}

func (HysteriaObfs) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("HysteriaObfs{[REDACTED]}")) }
func (Hysteria) Format(s fmt.State, _ rune)     { _, _ = s.Write([]byte("Hysteria{[REDACTED]}")) }
func (o *HysteriaObfs) UnmarshalJSON(b []byte) error {
	type plain HysteriaObfs
	var p plain
	if exact(b, &p, "type", "password", "min_packet_size", "max_packet_size") != nil {
		return bad()
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(b, &fields)
	for _, key := range []string{"min_packet_size", "max_packet_size"} {
		if value, ok := fields[key]; ok {
			var n int
			if json.Unmarshal(value, &n) != nil || n <= 0 {
				return bad()
			}
		}
	}
	*o = HysteriaObfs(p)
	return o.Validate()
}
func (o HysteriaObfs) Sizes() (int, int) {
	lo, hi := o.MinPacketSize, o.MaxPacketSize
	if lo == 0 {
		lo = 512
	}
	if hi == 0 {
		hi = 1200
	}
	return lo, hi
}
func (o HysteriaObfs) Validate() error {
	switch o.Type {
	case "none":
		if o.Password != "" || o.MinPacketSize != 0 || o.MaxPacketSize != 0 {
			return bad()
		}
	case "salamander":
		if len(o.Password) == 0 || len(o.Password) > 1024 || o.MinPacketSize != 0 || o.MaxPacketSize != 0 {
			return bad()
		}
	case "gecko":
		lo, hi := o.Sizes()
		if len(o.Password) == 0 || len(o.Password) > 1024 || lo < 14 || hi < lo || hi < 163 || hi > 2048 {
			return bad()
		}
	default:
		return bad()
	}
	return nil
}

// Native durations are seconds, following existing Hysteria QUIC settings.
// Ports is client-only. ServerPortRange is a Linux owned redirect range.
const maxHopSeconds = int64((1<<63 - 1) / int64(time.Second))

type HysteriaUDP struct {
	Ports           string `json:"ports,omitempty"`
	HopInterval     int    `json:"hop_interval,omitempty"`
	MinHopInterval  int    `json:"min_hop_interval,omitempty"`
	MaxHopInterval  int    `json:"max_hop_interval,omitempty"`
	ServerPortRange string `json:"server_port_range,omitempty"`
}

func (u *HysteriaUDP) UnmarshalJSON(b []byte) error {
	type plain HysteriaUDP
	var p plain
	if exact(b, &p, "ports", "hop_interval", "min_hop_interval", "max_hop_interval", "server_port_range") != nil {
		return bad()
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(b, &fields)
	for _, key := range []string{"hop_interval", "min_hop_interval", "max_hop_interval"} {
		if value, ok := fields[key]; ok {
			var n int
			if json.Unmarshal(value, &n) != nil || n <= 0 {
				return bad()
			}
		}
	}
	*u = HysteriaUDP(p)
	return u.Validate()
}
func (u HysteriaUDP) Validate() error {
	if u.Ports != "" {
		if _, e := ParseHysteriaPorts(u.Ports); e != nil {
			return bad()
		}
	}
	if u.ServerPortRange != "" {
		if u.Ports != "" || u.HopInterval != 0 || u.MinHopInterval != 0 || u.MaxHopInterval != 0 {
			return bad()
		}
		if _, _, e := HysteriaServerRange(u.ServerPortRange); e != nil {
			return bad()
		}
	}
	if u.Ports == "" && (u.HopInterval != 0 || u.MinHopInterval != 0 || u.MaxHopInterval != 0) {
		return bad()
	}
	if u.HopInterval != 0 && (u.MinHopInterval != 0 || u.MaxHopInterval != 0) {
		return bad()
	}
	if u.HopInterval < 0 || int64(u.HopInterval) > maxHopSeconds || u.HopInterval != 0 && u.HopInterval < 5 {
		return bad()
	}
	if u.MinHopInterval != 0 || u.MaxHopInterval != 0 {
		if u.MinHopInterval < 5 || u.MaxHopInterval < u.MinHopInterval || int64(u.MaxHopInterval) > maxHopSeconds {
			return bad()
		}
	}
	return nil
}
func (u HysteriaUDP) Interval() (time.Duration, error) {
	if e := u.Validate(); e != nil {
		return 0, e
	}
	if u.MinHopInterval != 0 {
		n, e := rand.Int(rand.Reader, big.NewInt(int64(u.MaxHopInterval-u.MinHopInterval)*int64(time.Second)+1))
		if e != nil {
			return 0, bad()
		}
		return time.Duration(u.MinHopInterval)*time.Second + time.Duration(n.Int64()), nil
	}
	n := u.HopInterval
	if n == 0 {
		n = 30
	}
	return time.Duration(n) * time.Second, nil
}

type portInterval struct{ lo, hi uint16 }

// PortSet stores sorted disjoint intervals, never textual range expansion.
type PortSet struct {
	ranges []portInterval
	count  int
}

func ParseHysteriaPorts(text string) (PortSet, error) {
	var p PortSet
	if text == "" || len(text) > 16384 {
		return p, bad()
	}
	number := func(s string) (uint16, error) {
		if s == "" || len(s) > 5 {
			return 0, bad()
		}
		for _, c := range s {
			if c < '0' || c > '9' {
				return 0, bad()
			}
		}
		n, e := strconv.ParseUint(s, 10, 16)
		if e != nil || n == 0 {
			return 0, bad()
		}
		return uint16(n), nil
	}
	for _, s := range strings.Split(text, ",") {
		a := strings.Split(s, "-")
		if len(a) > 2 {
			return PortSet{}, bad()
		}
		lo, e := number(a[0])
		if e != nil {
			return PortSet{}, bad()
		}
		hi := lo
		if len(a) == 2 {
			hi, e = number(a[1])
			if e != nil || hi < lo {
				return PortSet{}, bad()
			}
		}
		p.ranges = append(p.ranges, portInterval{lo, hi})
	}
	sort.Slice(p.ranges, func(i, j int) bool { return p.ranges[i].lo < p.ranges[j].lo })
	merged := p.ranges[:0]
	for _, r := range p.ranges {
		if len(merged) > 0 && int(r.lo) <= int(merged[len(merged)-1].hi)+1 {
			if r.hi > merged[len(merged)-1].hi {
				merged[len(merged)-1].hi = r.hi
			}
		} else {
			merged = append(merged, r)
		}
	}
	p.ranges = merged
	for _, r := range p.ranges {
		p.count += int(r.hi) - int(r.lo) + 1
	}
	return p, nil
}
func (p PortSet) Len() int { return p.count }
func (p PortSet) First() uint16 {
	if p.count == 0 {
		return 0
	}
	return p.ranges[0].lo
}
func (p PortSet) Contains(port uint16) bool {
	for _, r := range p.ranges {
		if port >= r.lo && port <= r.hi {
			return true
		}
	}
	return false
}
func (p PortSet) String() string {
	var a []string
	for _, r := range p.ranges {
		s := strconv.Itoa(int(r.lo))
		if r.hi != r.lo {
			s += "-" + strconv.Itoa(int(r.hi))
		}
		a = append(a, s)
	}
	return strings.Join(a, ",")
}
func (p PortSet) Select(exclude uint16) (uint16, error) {
	n := p.count
	skip := p.Contains(exclude) && n > 1
	if skip {
		n--
	}
	if n <= 0 {
		return 0, bad()
	}
	sample, e := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if e != nil {
		return 0, bad()
	}
	index := int(sample.Int64())
	for _, r := range p.ranges {
		length := int(r.hi) - int(r.lo) + 1
		if skip && exclude >= r.lo && exclude <= r.hi {
			length--
		}
		if index < length {
			v := int(r.lo) + index
			if skip && exclude >= r.lo && exclude <= r.hi && v >= int(exclude) {
				v++
			}
			return uint16(v), nil
		}
		index -= length
	}
	return 0, bad()
}
func HysteriaServerRange(s string) (uint16, uint16, error) {
	if strings.Count(s, "-") != 1 || strings.Contains(s, ",") {
		return 0, 0, bad()
	}
	p, e := ParseHysteriaPorts(s)
	if e != nil || len(p.ranges) != 1 || p.Len() < 2 {
		return 0, 0, bad()
	}
	return p.ranges[0].lo, p.ranges[0].hi, nil
}

func (h Hysteria) ClientOnly() bool {
	return h.Masquerade == nil && !h.DisableUDP && (h.UDP == nil || h.UDP.ServerPortRange == "")
}
func (h Hysteria) ClientProfile() Hysteria {
	out := Hysteria{Version: 2}
	if h.Obfs != nil {
		o := *h.Obfs
		out.Obfs = &o
	}
	if h.UDP != nil && h.UDP.ServerPortRange != "" {
		out.UDP = &HysteriaUDP{Ports: h.UDP.ServerPortRange}
	}
	return out
}

// PacketIdentity hashes configuration for loggable identity comparisons.
// Actual managers remain instance-scoped and never share a process-global pool.
func (h Hysteria) PacketIdentity() string {
	h = h.Clone()
	if h.UDP != nil && h.UDP.Ports != "" {
		if p, e := ParseHysteriaPorts(h.UDP.Ports); e == nil {
			h.UDP.Ports = p.String()
		}
	}
	b, _ := json.Marshal(h)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
