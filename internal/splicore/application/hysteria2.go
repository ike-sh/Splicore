package application

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	hm "github.com/sagernet/sing-box/internal/splicore/protocol/hysteria2"
)

type PolicyDraft = ports.PolicyDraft
type Hysteria2User struct {
	Name     string
	Enabled  bool
	Password secret.Value
	Policy   *PolicyDraft
}
type Hysteria2Document struct {
	Schema            int
	Name              string
	Listener, Display access.Endpoint
	Settings          hm.Settings
	Users             []Hysteria2User
}

func (Hysteria2Document) Format(s fmt.State, v rune) {
	_, _ = s.Write([]byte("Hysteria2Document{[REDACTED]}"))
}

type Hysteria2Plan = CreationPlan
type Hysteria2ApplyResult = CreationResult
type Hysteria2Commands interface {
	ValidateHysteria2(context.Context, json.RawMessage) error
	PlanHysteria2(context.Context, json.RawMessage) (Hysteria2Plan, error)
	ApplyHysteria2(context.Context, ApplyRequest) (Hysteria2ApplyResult, error)
	SetBinding(context.Context, identity.ID, BindingRequest) (identity.Transaction, error)
}

func DecodeHysteria2(b []byte) (Hysteria2Document, error) {
	d, err := (hm.Module{}).DecodeCreation(b)
	if err != nil {
		return Hysteria2Document{}, err
	}
	settings, _ := hm.Decode(d.Settings)
	out := Hysteria2Document{Schema: 1, Name: d.Name, Listener: d.Listener, Display: d.Display, Settings: settings}
	for _, u := range d.Users {
		out.Users = append(out.Users, Hysteria2User{Name: u.Name, Enabled: u.Enabled, Password: u.Payload.(access.PasswordPayload).Password, Policy: u.Policy})
	}
	return out, nil
}
func (s *Service) ValidateHysteria2(ctx context.Context, b json.RawMessage) error {
	return s.ValidateCreation(ctx, "hysteria2", b)
}
func (s *Service) PlanHysteria2(ctx context.Context, b json.RawMessage) (Hysteria2Plan, error) {
	p, err := s.PlanCreation(ctx, "hysteria2", b)
	return Hysteria2Plan(p), err
}
func (s *Service) ApplyHysteria2(ctx context.Context, r ApplyRequest) (Hysteria2ApplyResult, error) {
	return s.ApplyCreation(ctx, "hysteria2", r)
}
