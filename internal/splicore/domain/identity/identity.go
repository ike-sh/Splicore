// Package identity defines stable resource identity and commit primitives.
package identity

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type Code string

// RetiredRuntimeStateMessage is the fixed operator guidance safe to expose at
// the CLI boundary. Arbitrary error messages still remain redacted.
const RetiredRuntimeStateMessage = "retired Xray or transport-mask state retained; remove unsupported records with the previous experimental build before upgrade"

const (
	Invalid                      Code = "invalid"
	Conflict                     Code = "revision_conflict"
	NotFound                     Code = "not_found"
	Duplicate                    Code = "duplicate"
	NotImplemented               Code = "not_implemented"
	UnsupportedExport            Code = "unsupported_export"
	UnsupportedEngineForProtocol Code = "unsupported_engine_for_protocol"
	UnsupportedPolicyForEngine   Code = "unsupported_policy_for_engine"
	UnsupportedEngineFeature     Code = "unsupported_engine_feature"
	PortConflict                 Code = "port_conflict"
	Unavailable                  Code = "unavailable"
	Corrupt                      Code = "corrupt_state"
)

// Error contains only fixed, safe messages; never attach untrusted inputs.
type Error struct {
	Code    Code
	Message string
	Current Revision
}

func (e *Error) Error() string            { return string(e.Code) + ": " + e.Message }
func Err(code Code, message string) error { return &Error{Code: code, Message: message} }
func RevisionConflict(current Revision) error {
	return &Error{Code: Conflict, Message: "expected revision does not match committed state", Current: current}
}

type ID string

func NewID() (ID, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", Err(Unavailable, "identity entropy unavailable")
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	s := hex.EncodeToString(b[:])
	return ID(s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]), nil
}

func ParseID(s string) (ID, error) {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return "", Err(Invalid, "invalid resource ID")
	}
	compact := strings.ReplaceAll(s, "-", "")
	b, err := hex.DecodeString(compact)
	if err != nil || len(b) != 16 || s != strings.ToLower(s) || b[6]>>4 != 4 || b[8]>>6 != 2 {
		return "", Err(Invalid, "resource ID must be canonical random UUID v4")
	}
	return ID(s), nil
}
func (id ID) Validate() error { _, err := ParseID(string(id)); return err }

type Revision int64

func (r Revision) Next() (Revision, error) {
	if r < 0 || r == math.MaxInt64 {
		return 0, Err(Invalid, "revision overflow or invalid revision")
	}
	return r + 1, nil
}

func (r Revision) MarshalJSON() ([]byte, error) {
	if r < 0 {
		return nil, Err(Invalid, "negative revision")
	}
	return json.Marshal(strconv.FormatInt(int64(r), 10))
}

func (r *Revision) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) != nil || s == "" {
		return Err(Invalid, "revision must be a decimal string")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return Err(Invalid, "revision must be a decimal string")
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return Err(Invalid, "revision out of range")
	}
	*r = Revision(n)
	return nil
}

type Metadata map[string]string

// Metadata is deliberately limited to nonsecret display annotations.
func (m Metadata) Validate() error {
	if len(m) > 32 {
		return Err(Invalid, "too many metadata entries")
	}
	for k, v := range m {
		if !Label(k, 64) || !Label(v, 256) {
			return Err(Invalid, "invalid metadata entry")
		}
		key := strings.ToLower(k)
		for _, secret := range []string{"password", "psk", "secret", "token", "credential", "private", "uuid", "userkey"} {
			if strings.Contains(key, secret) {
				return Err(Invalid, "sensitive metadata key prohibited")
			}
		}
	}
	return nil
}
func (m Metadata) Format(s fmt.State, verb rune) { _, _ = s.Write([]byte("[metadata redacted]")) }
func Label(s string, max int) bool {
	if len(s) == 0 || len(s) > max || strings.TrimSpace(s) != s || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

type Stamp struct {
	Revision  Revision  `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func NewStamp(now time.Time) Stamp {
	return Stamp{Revision: 1, CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
}

func (s Stamp) Validate() error {
	if s.Revision < 1 || s.CreatedAt.IsZero() || s.UpdatedAt.Before(s.CreatedAt) || s.CreatedAt.Location() != time.UTC || s.UpdatedAt.Location() != time.UTC {
		return Err(Invalid, "invalid revision or UTC timestamps")
	}
	return nil
}

type TransactionState string

const (
	Pending   TransactionState = "pending"
	Committed TransactionState = "committed"
	Failed    TransactionState = "failed"
)

type Actor struct {
	Principal string `json:"principal"`
	RequestID ID     `json:"request_id"`
}

func (a Actor) Validate() error {
	if !Label(a.Principal, 128) {
		return Err(Invalid, "invalid actor")
	}
	return a.RequestID.Validate()
}

// Transaction is a journal identity, independent of any SQL transaction handle.
type Transaction struct {
	ID             ID               `json:"id"`
	State          TransactionState `json:"state"`
	BaseRevision   Revision         `json:"base_revision"`
	TargetRevision Revision         `json:"target_revision"`
	Actor          Actor            `json:"actor"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
	FailureCode    Code             `json:"failure_code,omitempty"`
}

func (t *Transaction) Finish(state TransactionState, now time.Time, code Code) error {
	if t.State != Pending || (state != Committed && state != Failed) || now.Before(t.CreatedAt) {
		return Err(Invalid, "invalid transaction transition")
	}
	t.State, t.UpdatedAt = state, now.UTC()
	if state == Failed {
		t.FailureCode = code
	}
	return nil
}

// DomainEvent is an allowlisted audit extension; it has no arbitrary payload.
type DomainEvent struct {
	TransactionID ID        `json:"transaction_id"`
	Actor         Actor     `json:"actor"`
	ResourceID    ID        `json:"resource_id"`
	Action        string    `json:"action"`
	Revision      Revision  `json:"revision"`
	At            time.Time `json:"at"`
}
