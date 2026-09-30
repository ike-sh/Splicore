// Package application is the common entry point for control transports.
package application

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	"github.com/sagernet/sing-box/internal/splicore/version"
)

type System struct {
	NodeID            identity.ID       `json:"node_id"`
	InstanceID        identity.ID       `json:"instance_id"`
	Version           version.Info      `json:"version"`
	ConfigSchema      int               `json:"config_schema"`
	DBSchema          int               `json:"db_schema"`
	ProtocolABI       int               `json:"protocol_abi"`
	CommittedRevision identity.Revision `json:"committed_revision"`
	Health            string            `json:"health"`
	Reasons           []string          `json:"reasons"`
	Foundation        Foundation        `json:"foundation"`
}

// Foundation describes only checks that the daemon has actually completed.
type Foundation struct {
	DatabaseStatus      string `json:"database_status"`
	PendingMigrations   int    `json:"pending_migrations"`
	PendingTransactions int    `json:"pending_transactions"`
	Protocols           int    `json:"protocols"`
	Engines             int    `json:"engines"`
	Exporters           int    `json:"exporters"`
}

// Features is a typed wire projection of grouped internal capabilities.
type Features struct {
	Implementation    string         `json:"implementation"`
	TCP               bool           `json:"tcp"`
	UDPTransport      bool           `json:"udp_transport"`
	UDPPayload        bool           `json:"udp_payload"`
	IPv4              bool           `json:"ipv4"`
	IPv6              bool           `json:"ipv6"`
	DomainEndpoint    bool           `json:"domain_endpoint"`
	NativeMultiUser   bool           `json:"multi_user_native"`
	NativeStats       ports.Support  `json:"native_stats"`
	AttributedPayload ports.Support  `json:"attributed_payload"`
	NativeQuota       ports.Support  `json:"quota"`
	NativeSpeedLimit  ports.Support  `json:"speed_limit"`
	MaxSessions       ports.Support  `json:"max_sessions"`
	UserMutation      ports.Mutation `json:"user_mutation"`
	ListenerMutation  ports.Mutation `json:"listener_mutation"`
	HotReload         bool           `json:"hot_reload"`
	TLS               bool           `json:"tls"`
	Reality           bool           `json:"reality"`
}
type QualifiedClient struct {
	Client   string `json:"client"`
	Version  string `json:"version"`
	Evidence string `json:"evidence"`
}
type Capability struct {
	Protocol         string             `json:"protocol"`
	WireVersion      string             `json:"wire_version"`
	FeatureProfile   string             `json:"feature_profile"`
	Availability     ports.Availability `json:"availability"`
	Qualification    string             `json:"qualification"`
	Features         Features           `json:"features"`
	QualifiedClients []QualifiedClient  `json:"qualified_clients"`
}
type CapabilityPage struct {
	Items            []Capability      `json:"items"`
	SnapshotRevision identity.Revision `json:"snapshot_revision"`
	NextCursor       string            `json:"next_cursor,omitempty"`
}
type Queries interface {
	System(context.Context) (System, error)
	Capabilities(context.Context, string, int) (CapabilityPage, error)
}
type Service struct {
	repo        ports.Repository
	protocols   *registry.Protocols
	engines     *registry.Engines
	exporters   *registry.Exporters
	instance    identity.ID
	build       version.Info
	fingerprint string
}

func New(repo ports.Repository, p *registry.Protocols, e *registry.Engines, x *registry.Exporters, build version.Info) (*Service, error) {
	if repo == nil || p == nil || e == nil || x == nil {
		return nil, identity.Err(identity.Invalid, "missing application dependency")
	}
	id, err := identity.NewID()
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(struct {
		Keys  []access.ProtocolKey
		Build version.Info
	}{p.Keys(), build})
	sum := sha256.Sum256(b)
	return &Service{repo: repo, protocols: p, engines: e, exporters: x, instance: id, build: build, fingerprint: hex.EncodeToString(sum[:])}, nil
}

func (s *Service) System(ctx context.Context) (System, error) {
	state, err := s.repo.State(ctx)
	if err != nil {
		return System{}, err
	}
	health := "degraded"
	reasons := []string{"foundation_only_runtime_not_implemented"}
	if state.PendingTransactions > 0 {
		health = "recovery_required"
		reasons = append(reasons, "pending_transaction_requires_review")
	}
	return System{NodeID: state.NodeID, InstanceID: s.instance, Version: s.build, ConfigSchema: version.ConfigSchema, DBSchema: state.Schema, ProtocolABI: version.ProtocolABI, CommittedRevision: state.Revision, Health: health, Reasons: reasons, Foundation: Foundation{DatabaseStatus: "ready", PendingMigrations: state.PendingMigrations, PendingTransactions: state.PendingTransactions, Protocols: len(s.protocols.Keys()), Engines: len(s.engines.Keys()), Exporters: len(s.exporters.Keys())}}, nil
}

func (s *Service) Capabilities(ctx context.Context, cursor string, limit int) (CapabilityPage, error) {
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 200 {
		return CapabilityPage{}, identity.Err(identity.Invalid, "limit must be between 1 and 200")
	}
	state, err := s.repo.State(ctx)
	if err != nil {
		return CapabilityPage{}, err
	}
	keys := s.protocols.Keys()
	offset := 0
	if cursor != "" {
		if len(cursor) > 256 {
			return CapabilityPage{}, identity.Err(identity.Invalid, "invalid capability cursor")
		}
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			return CapabilityPage{}, identity.Err(identity.Invalid, "invalid capability cursor")
		}
		parts := strings.Split(string(raw), ":")
		if len(parts) != 3 || parts[0] != strconv.FormatInt(int64(state.Revision), 10) || parts[2] != s.fingerprint {
			return CapabilityPage{}, identity.Err(identity.Invalid, "expired or incompatible capability cursor")
		}
		offset, err = strconv.Atoi(parts[1])
		if err != nil || offset < 1 || offset >= len(keys) {
			return CapabilityPage{}, identity.Err(identity.Invalid, "invalid capability cursor")
		}
	}
	end := min(offset+limit, len(keys))
	page := CapabilityPage{Items: []Capability{}, SnapshotRevision: state.Revision}
	for _, key := range keys[offset:end] {
		p, err := s.protocols.Get(key)
		if err != nil {
			return CapabilityPage{}, err
		}
		m := p.Metadata()
		c := p.Capabilities(ports.CapabilityContext{Platform: s.build.Platform})
		clients := []QualifiedClient{}
		for _, q := range c.Clients {
			if q.Evidence != "" {
				clients = append(clients, QualifiedClient{q.Client, q.Version, q.Evidence})
			}
		}
		page.Items = append(page.Items, Capability{Protocol: key.Protocol, WireVersion: key.WireVersion, FeatureProfile: key.FeatureProfile, Availability: m.Availability, Qualification: m.Qualification, Features: Features{Implementation: "placeholder", TCP: c.Transport.TCP, UDPTransport: c.Transport.UDPTransport, UDPPayload: c.Transport.UDPPayload, IPv4: c.Transport.IPv4, IPv6: c.Transport.IPv6, DomainEndpoint: c.Transport.DomainEndpoint, NativeMultiUser: c.Identity.MultiUserNative, NativeStats: c.Identity.NativeStats, AttributedPayload: c.Identity.AttributedPayload, NativeQuota: c.Policy.Quota, NativeSpeedLimit: c.Policy.SpeedLimit, MaxSessions: c.Policy.MaxSessions, UserMutation: c.Mutation.Users, ListenerMutation: c.Mutation.Listener, HotReload: c.Mutation.HotReload, TLS: c.Security.TLS, Reality: c.Security.Reality}, QualifiedClients: clients})
	}
	if end < len(keys) {
		page.NextCursor = base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, "%d:%d:%s", state.Revision, end, s.fingerprint))
	}
	return page, nil
}

func (s *Service) CreateAccount(ctx context.Context, name string, expected identity.Revision, actor identity.Actor) (access.Account, identity.Transaction, error) {
	id, err := identity.NewID()
	if err != nil {
		return access.Account{}, identity.Transaction{}, err
	}
	a := access.Account{ID: id, Name: name, Status: access.Active, Enabled: true, Metadata: identity.Metadata{}, Stamp: identity.NewStamp(time.Now())}
	if err = a.Validate(); err != nil {
		return access.Account{}, identity.Transaction{}, err
	}
	op, err := s.repo.Transact(ctx, expected, actor, func(w ports.Writer) error { return w.CreateAccount(a) })
	if err != nil {
		return access.Account{}, op, err
	}
	return a, op, nil
}

func (s *Service) UpdateAccount(ctx context.Context, a access.Account, resourceRevision, globalRevision identity.Revision, actor identity.Actor) (identity.Transaction, error) {
	if err := a.Validate(); err != nil {
		return identity.Transaction{}, err
	}
	return s.repo.Transact(ctx, globalRevision, actor, func(w ports.Writer) error { return w.UpdateAccount(a, resourceRevision) })
}

type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}
type Doctor struct {
	Version version.Info `json:"version"`
	Checks  []Check      `json:"checks"`
}

func (s *Service) Doctor(ctx context.Context, transport string) (Doctor, error) {
	state, err := s.repo.State(ctx)
	if err != nil {
		return Doctor{}, err
	}
	return Doctor{Version: s.build, Checks: []Check{{"platform", "pass", s.build.Platform}, {"storage", "pass", "committed SQLite available"}, {"db_schema", "pass", strconv.Itoa(state.Schema)}, {"migrations", "pass", strconv.Itoa(state.PendingMigrations) + " pending"}, {"transactions", "info", strconv.Itoa(state.PendingTransactions) + " pending"}, {"protocol_registry", "pass", strconv.Itoa(len(s.protocols.Keys())) + " placeholders"}, {"engine_registry", "pass", strconv.Itoa(len(s.engines.Keys())) + " metadata entries; runtime deferred"}, {"exporter_registry", "pass", strconv.Itoa(len(s.exporters.Keys())) + " placeholders"}, {"api_transport", "pass", transport}}}, nil
}
