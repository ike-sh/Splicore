// Package finalmask describes reusable TCP underlay masks, independently of protocols.
package finalmask

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
)

var ErrConfig = errors.New("invalid or unsupported TCP FinalMask settings")

// encoding/json folds struct names and accepts null scalar fields. Neither can
// erase explicit mask intent. Raw packet/settings bytes are validated separately.
func decodeExact(b []byte, dst any) error {
	if jsonstrict.Decode(b, dst) != nil {
		return ErrConfig
	}
	var shape any
	if json.Unmarshal(b, &shape) != nil {
		return ErrConfig
	}
	return exactShape(shape, reflect.TypeOf(dst).Elem())
}
func exactShape(v any, typ reflect.Type) error {
	if v == nil {
		return ErrConfig
	}
	if typ == reflect.TypeFor[json.RawMessage]() || typ == reflect.TypeFor[Range]() {
		return nil
	}
	if typ.Kind() == reflect.Pointer {
		return exactShape(v, typ.Elem())
	}
	switch typ.Kind() {
	case reflect.Struct:
		object, ok := v.(map[string]any)
		if !ok {
			return ErrConfig
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			fields[strings.Split(f.Tag.Get("json"), ",")[0]] = f.Type
		}
		for key, value := range object {
			field, ok := fields[key]
			if !ok {
				return ErrConfig
			}
			if e := exactShape(value, field); e != nil {
				return e
			}
		}
	case reflect.Slice:
		array, ok := v.([]any)
		if !ok {
			return ErrConfig
		}
		for _, item := range array {
			if e := exactShape(item, typ.Elem()); e != nil {
				return e
			}
		}
	}
	return nil
}

// Range accepts the pinned wire reference's integer and string range forms.
// All values are nonnegative and bounded before they reach timers or allocators.
type Range struct{ Min, Max int }

func (r *Range) UnmarshalJSON(b []byte) error {
	var s string
	if len(b) > 0 && b[0] == '"' {
		if json.Unmarshal(b, &s) != nil {
			return ErrConfig
		}
	} else {
		s = string(b)
	}
	v, e := ParseRange(s, 1<<30)
	if e != nil {
		return e
	}
	*r = v
	return nil
}
func (r Range) MarshalJSON() ([]byte, error) {
	if r.Min == r.Max {
		return []byte(strconv.Itoa(r.Min)), nil
	}
	return json.Marshal(fmt.Sprintf("%d-%d", r.Min, r.Max))
}
func ParseRange(s string, limit int) (Range, error) {
	p := strings.Split(s, "-")
	if len(p) < 1 || len(p) > 2 {
		return Range{}, ErrConfig
	}
	a, e := strconv.ParseUint(p[0], 10, 31)
	if e != nil || a > uint64(limit) {
		return Range{}, ErrConfig
	}
	b := a
	if len(p) == 2 {
		b, e = strconv.ParseUint(p[1], 10, 31)
		if e != nil || b > uint64(limit) {
			return Range{}, ErrConfig
		}
	}
	if b < a {
		return Range{}, ErrConfig
	}
	return Range{int(a), int(b)}, nil
}
func (r Range) Valid(limit int) bool { return r.Min >= 0 && r.Max >= r.Min && r.Max <= limit }

type Config struct {
	TCP []Mask `json:"tcp"`
}
type Mask struct {
	Type     string          `json:"type"`
	Settings json.RawMessage `json:"settings"`
}
type Header struct {
	Clients [][]Item `json:"clients,omitempty"`
	Servers [][]Item `json:"servers,omitempty"`
	Errors  [][]Item `json:"errors,omitempty"`
}
type Item struct {
	Delay     Range           `json:"delay,omitempty"`
	Rand      int             `json:"rand,omitempty"`
	RandRange *Range          `json:"randRange,omitempty"`
	Type      string          `json:"type,omitempty"`
	Packet    json.RawMessage `json:"packet,omitempty"`
}
type Fragment struct {
	Packets  string  `json:"packets,omitempty"`
	Length   *Range  `json:"length,omitempty"`
	Delay    *Range  `json:"delay,omitempty"`
	Lengths  []Range `json:"lengths,omitempty"`
	Delays   []Range `json:"delays,omitempty"`
	MaxSplit Range   `json:"maxSplit,omitempty"`
}
type Sudoku struct {
	Password     string   `json:"password"`
	ASCII        string   `json:"ascii,omitempty"`
	CustomTable  string   `json:"customTable,omitempty"`
	CustomTables []string `json:"customTables,omitempty"`
	PaddingMin   int      `json:"paddingMin,omitempty"`
	PaddingMax   int      `json:"paddingMax,omitempty"`
}

func (Config) Format(s fmt.State, _ rune) { fmt.Fprint(s, "FinalMask{[REDACTED]}") }
func (Mask) Format(s fmt.State, _ rune)   { fmt.Fprint(s, "TCPMask{[REDACTED]}") }
func (Sudoku) Format(s fmt.State, _ rune) { fmt.Fprint(s, "Sudoku{[REDACTED]}") }

// Redacted is a diagnostic projection; it is deliberately not runnable intent.
func (c Config) Redacted() Config {
	c = c.Clone()
	for i := range c.TCP {
		c.TCP[i].Settings = json.RawMessage(`"[REDACTED]"`)
	}
	return c
}
func (c Config) Clone() Config {
	out := Config{TCP: make([]Mask, len(c.TCP))}
	for i, m := range c.TCP {
		out.TCP[i] = Mask{m.Type, bytes.Clone(m.Settings)}
	}
	return out
}
func (c *Config) UnmarshalJSON(b []byte) error {
	type plain Config
	var p plain
	if len(b) > 12288 || decodeExact(b, &p) != nil {
		return ErrConfig
	}
	*c = Config(p)
	return c.Validate()
}
func Decode(m Mask) (any, error) {
	if len(m.Settings) == 0 || bytes.Equal(bytes.TrimSpace(m.Settings), []byte("null")) {
		return nil, ErrConfig
	}
	switch m.Type {
	case "header-custom":
		var h Header
		if decodeExact(m.Settings, &h) != nil {
			return nil, ErrConfig
		}
		total := 0
		for _, side := range [][][]Item{h.Clients, h.Servers, h.Errors} {
			if len(side) > 32 {
				return nil, ErrConfig
			}
			for _, seq := range side {
				if len(seq) > 64 {
					return nil, ErrConfig
				}
				for _, v := range seq {
					b, e := v.Bytes()
					if e != nil || !v.Delay.Valid(30000) || v.Rand < 0 || v.Rand > 4096 || v.Rand > 0 && v.Packet != nil || v.RandRange != nil && (!v.RandRange.Valid(255) || v.Rand == 0) {
						return nil, ErrConfig
					}
					total += len(b) + v.Rand
					if total > 65536 {
						return nil, ErrConfig
					}
				}
			}
		}
		return h, nil
	case "fragment":
		var f Fragment
		if decodeExact(m.Settings, &f) != nil || !f.MaxSplit.Valid(4096) {
			return nil, ErrConfig
		}
		f.Packets = strings.ToLower(f.Packets)
		if f.Packets != "" && strings.ToLower(f.Packets) != "tlshello" {
			r, e := ParseRange(f.Packets, 1<<30)
			if e != nil || r.Min == 0 {
				return nil, ErrConfig
			}
		}
		if len(f.Lengths) > 0 && f.Length != nil || len(f.Delays) > 0 && f.Delay != nil {
			return nil, ErrConfig
		}
		if len(f.Lengths) == 0 && f.Length != nil {
			f.Lengths = []Range{*f.Length}
		}
		if len(f.Delays) == 0 {
			f.Delays = []Range{{}}
			if f.Delay != nil {
				f.Delays[0] = *f.Delay
			}
		}
		if len(f.Lengths) == 0 || len(f.Lengths) > 64 || len(f.Delays) > 64 || f.Lengths[len(f.Lengths)-1].Min == 0 {
			return nil, ErrConfig
		}
		for _, r := range f.Lengths {
			if !r.Valid(65535) {
				return nil, ErrConfig
			}
		}
		for _, r := range f.Delays {
			if !r.Valid(30000) {
				return nil, ErrConfig
			}
		}
		return f, nil
	case "sudoku":
		var s Sudoku
		if decodeExact(m.Settings, &s) != nil || len(s.Password) > 1024 || s.PaddingMin < 0 || s.PaddingMax < s.PaddingMin || s.PaddingMax > 100 || len(s.CustomTables) > 16 {
			return nil, ErrConfig
		}
		s.ASCII = strings.ToLower(strings.TrimSpace(s.ASCII))
		switch s.ASCII {
		case "", "entropy", "prefer_entropy":
			s.ASCII = "prefer_entropy"
		case "ascii", "prefer_ascii":
			s.ASCII = "prefer_ascii"
		default:
			return nil, ErrConfig
		}
		// The reference ignores custom patterns in ASCII mode. Reject them explicitly.
		if s.ASCII == "prefer_ascii" && (s.CustomTable != "" || len(s.CustomTables) > 0) {
			return nil, ErrConfig
		}
		patterns := s.CustomTables
		if len(patterns) == 0 {
			patterns = []string{s.CustomTable}
		}
		seen := map[string]bool{}
		s.CustomTables = nil
		for _, p := range patterns {
			p = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), " ", ""))
			if p != "" && (len(p) != 8 || strings.Count(p, "x") != 2 || strings.Count(p, "p") != 2 || strings.Count(p, "v") != 4) {
				return nil, ErrConfig
			}
			if !seen[p] {
				s.CustomTables = append(s.CustomTables, p)
				seen[p] = true
			}
		}
		return s, nil
	default:
		return nil, ErrConfig
	}
}
func (c Config) Validate() error {
	if len(c.TCP) == 0 || len(c.TCP) > 8 {
		return ErrConfig
	}
	for _, m := range c.TCP {
		if _, e := Decode(m); e != nil {
			return e
		}
	}
	return nil
}
func (v Item) Bytes() ([]byte, error) {
	if v.Packet == nil {
		if v.Type != "" {
			return nil, ErrConfig
		}
		return nil, nil
	}
	if bytes.Equal(bytes.TrimSpace(v.Packet), []byte("null")) {
		return nil, ErrConfig
	}
	var b []byte
	var s string
	var e error
	switch strings.ToLower(v.Type) {
	case "", "array": // Numeric arrays and base64 strings follow encoding/json []byte semantics.
		e = json.Unmarshal(v.Packet, &b)
	case "str", "hex", "base64":
		e = json.Unmarshal(v.Packet, &s)
		if e == nil {
			switch strings.ToLower(v.Type) {
			case "str":
				b = []byte(s)
			case "hex":
				b, e = hex.DecodeString(s)
			case "base64":
				b, e = base64.StdEncoding.Strict().DecodeString(s)
			}
		}
	default:
		return nil, ErrConfig
	}
	if e != nil || len(b) > 4096 {
		return nil, ErrConfig
	}
	return b, nil
}
