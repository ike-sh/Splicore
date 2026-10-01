package application

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	sm "github.com/sagernet/sing-box/internal/splicore/protocol/snell"
	"io"
	"net/netip"
	"sync"
	"time"
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
func StrictJSON(b []byte, v any) error {
	if len(b) > 65536 {
		return identity.Err(identity.Invalid, "document exceeds limit")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return identity.Err(identity.Invalid, "document too deep")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		if delim != '{' && delim != '[' {
			return identity.Err(identity.Invalid, "invalid structure")
		}
		seen := map[string]bool{}
		for d.More() {
			if delim == '{' {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return identity.Err(identity.Invalid, "duplicate JSON field")
				}
				seen[s] = true
			}
			if e := walk(depth + 1); e != nil {
				return e
			}
		}
		_, e = d.Token()
		return e
	}
	if walk(0) != nil || d.Decode(new(any)) != io.EOF {
		return identity.Err(identity.Invalid, "invalid JSON document")
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return identity.Err(identity.Invalid, "unknown or invalid document field")
	}
	return nil
}
func DecodeSnell(b []byte) (SnellDocument, error) {
	var w struct {
		Schema      int             `json:"schema"`
		AccountName string          `json:"account_name"`
		Name        string          `json:"name"`
		Listener    access.Endpoint `json:"listener"`
		Display     access.Endpoint `json:"display_endpoint"`
		Settings    json.RawMessage `json:"settings"`
		PSK         json.RawMessage `json:"psk"`
	}
	if e := StrictJSON(b, &w); e != nil {
		return SnellDocument{}, e
	}
	settings, e := sm.Decode(w.Settings)
	if e != nil {
		return SnellDocument{}, e
	}
	var supplied string
	if len(w.PSK) > 0 {
		if json.Unmarshal(w.PSK, &supplied) != nil || sm.ValidatePSK(secret.New(supplied)) != nil {
			return SnellDocument{}, identity.Err(identity.Invalid, "invalid supplied Snell PSK")
		}
	}
	d := SnellDocument{w.Schema, w.AccountName, w.Name, w.Listener, w.Display, settings, secret.New(supplied)}
	if ip, err := netip.ParseAddr(d.Listener.Host); err != nil || ip.Zone() != "" {
		return SnellDocument{}, identity.Err(identity.Invalid, "listener requires an IP address")
	}
	if d.Schema != 1 || !identity.Label(d.Name, 128) || !identity.Label(d.AccountName, 128) || d.Listener.Validate() != nil || d.Display.Validate() != nil {
		return SnellDocument{}, identity.Err(identity.Invalid, "invalid Snell document")
	}
	if !d.PSK.Empty() {
		if e = sm.ValidatePSK(d.PSK); e != nil {
			return SnellDocument{}, e
		}
	}
	return d, nil
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
type InboundView struct {
	Inbound   access.Inbound `json:"inbound"`
	BindingID identity.ID    `json:"binding_id"`
	AccountID identity.ID    `json:"account_id"`
	Health    string         `json:"health"`
	Stats     ports.Stats    `json:"stats"`
}
type InboundPage struct {
	Items    []InboundView     `json:"items"`
	Revision identity.Revision `json:"snapshot_revision"`
}
type ExportRequest struct {
	Format        ports.Format `json:"format"`
	ClientVersion string       `json:"client_version"`
}
type ExportResult struct {
	Target            ports.Format `json:"format"`
	ClientVersion     string       `json:"client_version"`
	ServerVersion     int          `json:"server_version"`
	ClientWireVersion int          `json:"client_wire_version"`
	Compatibility     string       `json:"compatibility"`
	Content           string       `json:"content"`
}

func (e ExportResult) Format(f fmt.State, v rune) { _, _ = f.Write([]byte("Export{[REDACTED]}")) }

type DisplayRequest struct {
	Endpoint         access.Endpoint   `json:"endpoint"`
	ResourceRevision identity.Revision `json:"resource_revision"`
	Revision         identity.Revision `json:"revision"`
}
type InboundCommands interface {
	Inbounds(context.Context) (InboundPage, error)
	Inbound(context.Context, identity.ID) (InboundView, error)
	ValidateSnell(context.Context, json.RawMessage) error
	PlanSnell(context.Context, json.RawMessage) (Plan, error)
	ApplySnell(context.Context, ApplyRequest) (ApplyResult, error)
	ExportSnell(context.Context, identity.ID, ExportRequest) (ExportResult, error)
	SetDisplay(context.Context, identity.ID, DisplayRequest) (identity.Transaction, error)
}
type runtimeState struct {
	mu      sync.Mutex
	repo    ports.RuntimeRepository
	handles map[identity.ID]ports.RuntimeHandle
	key     [32]byte
	closed  bool
}

func accountAllowed(a access.Account) bool {
	return a.Enabled && a.Status == access.Active && (a.ExpiresAt == nil || time.Now().Before(*a.ExpiresAt))
}
func (s *Service) EnableRuntime(ctx context.Context) error {
	r, ok := s.repo.(ports.RuntimeRepository)
	if !ok {
		return identity.Err(identity.Unavailable, "runtime repository unavailable")
	}
	state := &runtimeState{repo: r, handles: map[identity.ID]ports.RuntimeHandle{}}
	if _, e := rand.Read(state.key[:]); e != nil {
		return identity.Err(identity.Unavailable, "plan entropy unavailable")
	}
	s.runtime = state
	if e := r.RecoverPending(ctx); e != nil {
		return e
	}
	snapshot, e := r.State(ctx)
	if e != nil {
		return e
	}
	if snapshot.PendingTransactions > 0 {
		return identity.Err(identity.Unavailable, "unrecognized pending operation requires review")
	}
	inbounds, e := r.Inbounds(ctx)
	if e != nil {
		return e
	}
	for _, i := range inbounds {
		b, e := r.Binding(ctx, i.ID)
		if e != nil {
			s.CloseRuntime(context.Background())
			return e
		}
		a, e := r.Account(ctx, b.AccountID)
		if e != nil || !accountAllowed(a) {
			s.CloseRuntime(context.Background())
			return identity.Err(identity.Invalid, "account unavailable for runtime")
		}
		c, e := r.RevealCredential(ctx, b.CredentialID)
		if e != nil {
			s.CloseRuntime(context.Background())
			return e
		}
		h, e := s.prepare(ctx, ports.RuntimeIntent{Inbound: i, Bindings: []access.Binding{b}, Credentials: []access.Credential{c}, Revision: snapshot.Revision})
		if e != nil {
			s.CloseRuntime(context.Background())
			return e
		}
		if e = h.Start(ctx); e == nil {
			e = h.Health(ctx)
		}
		if e != nil {
			_ = h.Close(context.Background())
			s.CloseRuntime(context.Background())
			return e
		}
		h.Activate()
		state.handles[i.ID] = h
	}
	return nil
}
func (s *Service) prepare(ctx context.Context, in ports.RuntimeIntent) (ports.RuntimeHandle, error) {
	p, e := s.protocols.Get(in.Inbound.Protocol)
	if e != nil {
		return nil, e
	}
	in, e = p.BuildRuntime(ctx, in)
	if e != nil {
		return nil, e
	}
	eng, e := s.engines.Get(in.Inbound.Engine)
	if e != nil {
		return nil, e
	}
	prepared, e := eng.Compile(ctx, in)
	if e != nil {
		return nil, e
	}
	h, ok := prepared.(ports.RuntimeHandle)
	if !ok {
		_ = prepared.Close(ctx)
		return nil, identity.Err(identity.Unavailable, "runtime lifecycle unavailable")
	}
	return h, nil
}
func (s *Service) CloseRuntime(ctx context.Context) error {
	if s.runtime == nil {
		return nil
	}
	r := s.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	var err error
	for id, h := range r.handles {
		if e := h.Close(ctx); e != nil {
			err = e
		}
		delete(r.handles, id)
	}
	return err
}
func (s *Service) ValidateSnell(_ context.Context, b json.RawMessage) error {
	d, e := DecodeSnell(b)
	if e != nil {
		return e
	}
	i, _, _, _, e := s.resources(d)
	if e != nil {
		return e
	}
	p, e := s.protocols.Get(i.Protocol)
	if e != nil {
		return e
	}
	return p.ValidateInbound(i)
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
	return Plan{s.digest(b, state.Revision), state.Revision, d.Settings.Version, d.Listener, d.Display, true}, nil
}
func (s *Service) digest(b []byte, r identity.Revision) string {
	var compact bytes.Buffer
	_ = json.Compact(&compact, b)
	b = compact.Bytes()
	h := hmac.New(sha256.New, s.runtime.key[:])
	_, _ = h.Write(b)
	_, _ = fmt.Fprintf(h, "/%d", r)
	return hex.EncodeToString(h.Sum(nil))
}
func (s *Service) resources(d SnellDocument) (access.Inbound, access.Account, access.Binding, access.Credential, error) {
	ids := make([]identity.ID, 6)
	for n := range ids {
		id, e := identity.NewID()
		if e != nil {
			return access.Inbound{}, access.Account{}, access.Binding{}, access.Credential{}, e
		}
		ids[n] = id
	}
	stamp := identity.NewStamp(time.Now())
	data, _ := json.Marshal(d.Settings)
	a := access.Account{ID: ids[1], Name: d.AccountName, Status: access.Active, Enabled: true, Metadata: identity.Metadata{}, Stamp: stamp}
	i := access.Inbound{ID: ids[0], NodeID: s.instance, Name: d.Name, Protocol: sm.Key(d.Settings.Version), Engine: "native", Enabled: true, Listeners: []access.Listener{{ID: ids[5], Transport: "tcp", Endpoint: d.Listener}}, DisplayEndpoints: []access.DisplayEndpoint{{ID: ids[4], Endpoint: d.Display}}, Tags: []string{}, Settings: access.Settings{Schema: 1, Data: data}, Stamp: stamp}
	c := access.Credential{ID: ids[3], OwnerAccountID: &a.ID, Kind: access.PSK, Schema: 1, State: "active", Payload: access.PSKPayload{Key: d.PSK}, Stamp: stamp}
	b := access.Binding{ID: ids[2], AccountID: a.ID, InboundID: i.ID, CredentialID: c.ID, Enabled: true, Stamp: stamp}
	return i, a, b, c, nil
}
func (s *Service) ApplySnell(ctx context.Context, req ApplyRequest) (ApplyResult, error) {
	if s.runtime == nil {
		return ApplyResult{}, identity.Err(identity.NotImplemented, "runtime unavailable")
	}
	r := s.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ApplyResult{}, identity.Err(identity.Unavailable, "runtime closed")
	}
	if e := s.ValidateSnell(ctx, req.Document); e != nil {
		return ApplyResult{}, e
	}
	if len(req.Digest) != 64 || !hmac.Equal([]byte(req.Digest), []byte(s.digest(req.Document, req.Revision))) {
		return ApplyResult{}, identity.Err(identity.Invalid, "plan digest mismatch or daemon restarted")
	}
	d, _ := DecodeSnell(req.Document)
	if d.PSK.Empty() {
		psk, e := sm.GeneratePSK()
		if e != nil {
			return ApplyResult{}, e
		}
		d.PSK = psk
	}
	i, a, b, c, e := s.resources(d)
	if e != nil {
		return ApplyResult{}, e
	}
	state, e := s.repo.State(ctx)
	if e != nil {
		return ApplyResult{}, e
	}
	i.NodeID = state.NodeID
	current, e := r.repo.Inbounds(ctx)
	if e != nil {
		return ApplyResult{}, e
	}
	if len(current) >= 64 {
		return ApplyResult{}, identity.Err(identity.Invalid, "Phase 2 supports at most 64 managed inbounds")
	}
	if state.Revision != req.Revision {
		return ApplyResult{}, identity.RevisionConflict(state.Revision)
	}
	h, e := s.prepare(ctx, ports.RuntimeIntent{Inbound: i, Bindings: []access.Binding{b}, Credentials: []access.Credential{c}, Revision: req.Revision})
	if e != nil {
		return ApplyResult{}, e
	}
	actor, e := localActor()
	if e != nil {
		_ = h.Close(context.Background())
		return ApplyResult{}, e
	}
	op, e := r.repo.BeginOperation(ctx, req.Revision, actor)
	if e != nil {
		_ = h.Close(context.Background())
		return ApplyResult{}, e
	}
	committed := false
	defer func() {
		if !committed {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = h.Close(cleanup)
			_ = r.repo.FailOperation(cleanup, op)
		}
	}()
	if e = h.Start(ctx); e == nil {
		e = h.Health(ctx)
	}
	if e != nil {
		return ApplyResult{}, e
	}
	e = r.repo.CommitOperation(ctx, op, func(w ports.Writer) error {
		if e := w.CreateAccount(a); e != nil {
			return e
		}
		if e := w.CreateInbound(i); e != nil {
			return e
		}
		if e := w.CreateCredential(c); e != nil {
			return e
		}
		return w.CreateBinding(b)
	})
	if e != nil {
		return ApplyResult{}, safeOperation(e)
	}
	committed = true
	h.Activate()
	r.handles[i.ID] = h
	_ = op.Finish(identity.Committed, time.Now(), "")
	return ApplyResult{i.ID, a.ID, b.ID, op}, nil
}
func localActor() (identity.Actor, error) {
	id, e := identity.NewID()
	return identity.Actor{Principal: "local-control", RequestID: id}, e
}
func (s *Service) Inbounds(ctx context.Context) (InboundPage, error) {
	if s.runtime == nil {
		return InboundPage{}, identity.Err(identity.NotImplemented, "runtime unavailable")
	}
	r := s.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	return s.views(ctx)
}
func (s *Service) views(ctx context.Context) (InboundPage, error) {
	state, e := s.repo.State(ctx)
	if e != nil {
		return InboundPage{}, e
	}
	in, e := s.runtime.repo.Inbounds(ctx)
	if e != nil {
		return InboundPage{}, e
	}
	out := InboundPage{Items: []InboundView{}, Revision: state.Revision}
	for _, i := range in {
		b, e := s.runtime.repo.Binding(ctx, i.ID)
		if e != nil {
			return InboundPage{}, e
		}
		v := InboundView{Inbound: i, BindingID: b.ID, AccountID: b.AccountID, Health: "stopped"}
		if h := s.runtime.handles[i.ID]; h != nil {
			v.Stats = h.Stats()
			if h.Health(ctx) == nil {
				v.Health = "healthy"
			} else {
				v.Health = "degraded"
			}
		}
		out.Items = append(out.Items, v)
	}
	return out, nil
}
func (s *Service) Inbound(ctx context.Context, id identity.ID) (InboundView, error) {
	if e := id.Validate(); e != nil {
		return InboundView{}, e
	}
	p, e := s.Inbounds(ctx)
	if e != nil {
		return InboundView{}, e
	}
	for _, v := range p.Items {
		if v.Inbound.ID == id {
			return v, nil
		}
	}
	return InboundView{}, identity.Err(identity.NotFound, "inbound not found")
}
func (s *Service) ExportSnell(ctx context.Context, id identity.ID, req ExportRequest) (ExportResult, error) {
	if s.runtime == nil {
		return ExportResult{}, identity.Err(identity.NotImplemented, "runtime unavailable")
	}
	r := s.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	page, e := s.views(ctx)
	if e != nil {
		return ExportResult{}, e
	}
	var i access.Inbound
	found := false
	for _, v := range page.Items {
		if v.Inbound.ID == id {
			i = v.Inbound
			found = true
		}
	}
	if !found {
		return ExportResult{}, identity.Err(identity.NotFound, "inbound not found")
	}
	b, e := r.repo.Binding(ctx, id)
	if e != nil {
		return ExportResult{}, e
	}
	a, e := r.repo.Account(ctx, b.AccountID)
	if e != nil || !accountAllowed(a) {
		return ExportResult{}, identity.Err(identity.Invalid, "account unavailable for export")
	}
	c, e := r.repo.RevealCredential(ctx, b.CredentialID)
	if e != nil {
		return ExportResult{}, e
	}
	p, e := s.protocols.Get(i.Protocol)
	if e != nil {
		return ExportResult{}, e
	}
	profile, e := p.BuildClientProfile(ctx, ports.AuthorizedBinding{Inbound: i, Binding: b, Credential: c})
	if e != nil {
		return ExportResult{}, e
	}
	x, e := s.exporters.Get(req.Format)
	if e != nil {
		return ExportResult{}, e
	}
	content, e := x.Export(ctx, profile, ports.ExportTarget{Format: req.Format, ClientVersion: req.ClientVersion})
	if e != nil {
		return ExportResult{}, e
	}
	settings, _ := sm.Decode(i.Settings.Data)
	wire := settings.Version
	compat := "exact"
	if wire == 5 {
		wire = 4
		compat = "v4 TCP/UDP client to v5 server; QUIC Proxy Mode unavailable"
	}
	return ExportResult{req.Format, req.ClientVersion, settings.Version, wire, compat, string(content)}, nil
}
func (s *Service) SetDisplay(ctx context.Context, id identity.ID, req DisplayRequest) (identity.Transaction, error) {
	if s.runtime == nil {
		return identity.Transaction{}, identity.Err(identity.NotImplemented, "runtime unavailable")
	}
	r := s.runtime
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return identity.Transaction{}, identity.Err(identity.Unavailable, "runtime closed")
	}
	a, e := localActor()
	if e != nil {
		return identity.Transaction{}, e
	}
	return r.repo.UpdateDisplay(ctx, id, req.Endpoint, req.ResourceRevision, req.Revision, a)
}

func safeOperation(err error) error {
	var de *identity.Error
	if errors.As(err, &de) {
		if de.Code == identity.Conflict {
			return identity.RevisionConflict(de.Current)
		}
		return identity.Err(de.Code, "runtime operation rejected")
	}
	return identity.Err(identity.Unavailable, "runtime operation failed")
}
