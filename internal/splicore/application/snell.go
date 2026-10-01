package application

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/jsonstrict"
	sm "github.com/sagernet/sing-box/internal/splicore/protocol/snell"
)

type SnellDocument struct {
	Schema      int             `json:"schema"`
	AccountName string          `json:"account_name"`
	Name        string          `json:"name"`
	Listener    access.Endpoint `json:"listener"`
	Display     access.Endpoint `json:"display_endpoint"`
	Settings    sm.Settings     `json:"settings"`
	PSK         secret.Value    `json:"-"`
}

func (d SnellDocument) Format(f fmt.State, v rune) {
	_, _ = f.Write([]byte("SnellDocument{[REDACTED]}"))
}
func StrictJSON(b []byte, v any) error { return jsonstrict.Decode(b, v) }
func DecodeSnell(b []byte) (SnellDocument, error) {
	d, err := sm.DecodeSnell(b)
	return SnellDocument{Schema: d.Schema, AccountName: d.AccountName, Name: d.Name, Listener: d.Listener, Display: d.Display, Settings: d.Settings, PSK: d.PSK}, err
}

type Plan struct {
	Digest        string            `json:"digest"`
	Revision      identity.Revision `json:"revision"`
	ServerVersion int               `json:"server_version"`
	Listener      access.Endpoint   `json:"listener"`
	Display       access.Endpoint   `json:"display_endpoint"`
	SingleBinding bool              `json:"single_binding"`
}
type ApplyRequest struct {
	Document json.RawMessage   `json:"document"`
	Digest   string            `json:"digest"`
	Revision identity.Revision `json:"revision"`
}

func (a ApplyRequest) Format(f fmt.State, v rune) { _, _ = f.Write([]byte("ApplyRequest{[REDACTED]}")) }

type ApplyResult struct {
	InboundID   identity.ID          `json:"inbound_id"`
	AccountID   identity.ID          `json:"account_id"`
	BindingID   identity.ID          `json:"binding_id"`
	Transaction identity.Transaction `json:"transaction"`
}
type InboundCommands interface {
	Inbounds(context.Context) (InboundPage, error)
	Inbound(context.Context, identity.ID) (InboundView, error)
	ValidateSnell(context.Context, json.RawMessage) error
	PlanSnell(context.Context, json.RawMessage) (Plan, error)
	ApplySnell(context.Context, ApplyRequest) (ApplyResult, error)
	ExportSnell(context.Context, identity.ID, ExportRequest) (ExportResult, error)
	ExportClient(context.Context, identity.ID, ExportRequest) (ExportResult, error)
	SetDisplay(context.Context, identity.ID, DisplayRequest) (identity.Transaction, error)
}

func (s *Service) ValidateSnell(ctx context.Context, b json.RawMessage) error {
	return s.ValidateCreation(ctx, "snell", b)
}
func (s *Service) PlanSnell(ctx context.Context, b json.RawMessage) (Plan, error) {
	if e := s.ValidateSnell(ctx, b); e != nil {
		return Plan{}, e
	}
	if s.runtime == nil {
		return Plan{}, identity.Err(identity.NotImplemented, "runtime unavailable")
	}
	d, _ := DecodeSnell(b)
	state, e := s.repo.State(ctx)
	if e != nil {
		return Plan{}, e
	}
	return Plan{s.creationDigest("snell", b, state.Revision), state.Revision, d.Settings.Version, d.Listener, d.Display, true}, nil
}
func (s *Service) ApplySnell(ctx context.Context, req ApplyRequest) (ApplyResult, error) {
	v, err := s.ApplyCreation(ctx, "snell", req)
	if err != nil {
		return ApplyResult{}, err
	}
	return ApplyResult{InboundID: v.InboundID, AccountID: v.Bindings[0].AccountID, BindingID: v.Bindings[0].BindingID, Transaction: v.Transaction}, nil
}
