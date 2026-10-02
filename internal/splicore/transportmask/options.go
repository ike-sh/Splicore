// Package transportmask defines bounded transport requirements, not mask algorithms.
package transportmask

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/jsonstrict"
)

type Sudoku struct {
	ASCII      string `json:"ascii"`
	PaddingMin int    `json:"padding_min"`
	PaddingMax int    `json:"padding_max"`
}

// Require every parameter explicitly; JSON null must not silently become zero.
func (s *Sudoku) UnmarshalJSON(b []byte) error {
	var fields struct {
		ASCII      *string `json:"ascii"`
		PaddingMin *int    `json:"padding_min"`
		PaddingMax *int    `json:"padding_max"`
	}
	if len(b) > 1024 || jsonstrict.Decode(b, &fields) != nil || fields.ASCII == nil || fields.PaddingMin == nil || fields.PaddingMax == nil {
		return invalid()
	}
	*s = Sudoku{ASCII: *fields.ASCII, PaddingMin: *fields.PaddingMin, PaddingMax: *fields.PaddingMax}
	return nil
}

var _ json.Unmarshaler = (*Sudoku)(nil)

type TCPMask struct {
	Type     string  `json:"type"`
	Settings *Sudoku `json:"settings"`
}
type FinalMask struct {
	TCP []TCPMask `json:"tcp"`
}
type Options struct {
	FinalMask *FinalMask `json:"finalmask"`
}

func (o Options) Validate() error {
	if o.FinalMask == nil || len(o.FinalMask.TCP) != 1 {
		return invalid()
	}
	m := o.FinalMask.TCP[0]
	// Only the independently qualified NoBrand-compatible profile is exposed.
	if m.Type != "sudoku" || m.Settings == nil || m.Settings.ASCII != "prefer_ascii" || m.Settings.PaddingMin != 0 || m.Settings.PaddingMax != 3 {
		return invalid()
	}
	return nil
}
func invalid() error { return identity.Err(identity.Invalid, "invalid transport feature options") }
func ValidatePassword(p secret.Value) error {
	s := p.Reveal()
	if len(s) != 32 {
		return invalid()
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return invalid()
		}
	}
	return nil
}
func GeneratePassword() (secret.Value, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return secret.Value{}, identity.Err(identity.Unavailable, "transport secret entropy unavailable")
	}
	defer clear(b[:])
	return secret.New(hex.EncodeToString(b[:])), nil
}

// ClientRequirements contains a client-needed shared transport secret. It never
// contains a server-only key, an engine ID, a PID or runtime artifact identity.
type ClientRequirements struct {
	Options  Options      `json:"options"`
	Password secret.Value `json:"-"`
}

func (ClientRequirements) Format(f fmt.State, verb rune) {
	_, _ = f.Write([]byte("TransportRequirements{[REDACTED]}"))
}
func (c ClientRequirements) Validate() error {
	if err := c.Options.Validate(); err != nil {
		return err
	}
	return ValidatePassword(c.Password)
}
