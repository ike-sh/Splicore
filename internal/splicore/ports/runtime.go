package ports

import (
	"context"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"strconv"
)

// RuntimeHandle is prepared without network I/O, started with admission closed,
// and activated only after the domain commit succeeds.
type RuntimeHandle interface {
	PreparedRuntime
	Start(context.Context) error
	Health(context.Context) error
	Activate()
	Stats() Stats
}
type Stats struct {
	Upload   int64 `json:"upload_bytes"`
	Download int64 `json:"download_bytes"`
	Sessions int64 `json:"sessions_total"`
	Active   int64 `json:"sessions_active"`
}

func (s Stats) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Upload   string `json:"upload_bytes"`
		Download string `json:"download_bytes"`
		Sessions string `json:"sessions_total"`
		Active   string `json:"sessions_active"`
	}{strconv.FormatInt(s.Upload, 10), strconv.FormatInt(s.Download, 10), strconv.FormatInt(s.Sessions, 10), strconv.FormatInt(s.Active, 10)})
}
func (s *Stats) UnmarshalJSON(b []byte) error {
	var v struct {
		Upload   string `json:"upload_bytes"`
		Download string `json:"download_bytes"`
		Sessions string `json:"sessions_total"`
		Active   string `json:"sessions_active"`
	}
	if json.Unmarshal(b, &v) != nil {
		return identity.Err(identity.Invalid, "invalid stats response")
	}
	values := []string{v.Upload, v.Download, v.Sessions, v.Active}
	out := []*int64{&s.Upload, &s.Download, &s.Sessions, &s.Active}
	for n, value := range values {
		v, e := strconv.ParseInt(value, 10, 64)
		if e != nil || v < 0 {
			return identity.Err(identity.Invalid, "invalid stats counter")
		}
		*out[n] = v
	}
	return nil
}

// RuntimeRepository separates durable intent from short SQL commit callbacks.
type RuntimeRepository interface {
	Repository
	Inbounds(context.Context) ([]access.Inbound, error)
	Binding(context.Context, identity.ID) (access.Binding, error)
	RevealCredential(context.Context, identity.ID) (access.Credential, error)
	BeginOperation(context.Context, identity.Revision, identity.Actor) (identity.Transaction, error)
	CommitOperation(context.Context, identity.Transaction, func(Writer) error) error
	FailOperation(context.Context, identity.Transaction) error
	RecoverPending(context.Context) error
	UpdateDisplay(context.Context, identity.ID, access.Endpoint, identity.Revision, identity.Revision, identity.Actor) (identity.Transaction, error)
}

// MultiBindingRepository is the bounded runtime extension, separate from ordinary reads.
type MultiBindingRepository interface {
	RuntimeRepository
	Bindings(context.Context, identity.ID) ([]access.Binding, error)
	BeginRuntimeOperation(context.Context, identity.Revision, identity.Actor, string) (identity.Transaction, error)
}

type BindingWriter interface {
	SetBindingEnabled(identity.ID, bool, identity.Revision) error
}
type AttributedStats interface{ BindingStats(identity.ID) Stats }
