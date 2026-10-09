// Package application is the common entry point for control transports.
package application

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"strconv"
	"strings"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/clientruntime"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/version"
)

type System struct {
	Providers         ProviderDiagnostics    `json:"providers"`
	ServerRuntimes    []ServerRuntimeSummary `json:"server_runtimes"`
	ClientRuntime     *clientruntime.Status  `json:"client_runtime,omitempty"`
	NodeID            identity.ID            `json:"node_id"`
	InstanceID        identity.ID            `json:"instance_id"`
	Version           version.Info           `json:"version"`
	ConfigSchema      int                    `json:"config_schema"`
	DBSchema          int                    `json:"db_schema"`
	ProtocolABI       int                    `json:"protocol_abi"`
	CommittedRevision identity.Revision      `json:"committed_revision"`
	Health            string                 `json:"health"`
	Reasons           []string               `json:"reasons"`
	Foundation        Foundation             `json:"foundation"`
	Engines           []ports.EngineStatus   `json:"engines"`
}

// Foundation describes only checks that the daemon has actually completed.
type ServerRuntimeSummary struct {
	ID       identity.ID        `json:"id"`
	Protocol access.ProtocolKey `json:"protocol"`
	Engine   string             `json:"engine"`
	Health   string             `json:"health"`
}

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
	Implementation      string         `json:"implementation"`
	TCP                 bool           `json:"tcp"`
	UDPTransport        bool           `json:"udp_transport"`
	UDPPayload          bool           `json:"udp_payload"`
	IPv4                bool           `json:"ipv4"`
	IPv6                bool           `json:"ipv6"`
	DomainEndpoint      bool           `json:"domain_endpoint"`
	NativeMultiUser     bool           `json:"multi_user_native"`
	NativeStats         ports.Support  `json:"native_stats"`
	PerUserStats        bool           `json:"per_user_stats"`
	HotUserUpdate       bool           `json:"hot_user_update"`
	AttributedPayload   ports.Support  `json:"attributed_payload"`
	NativeQuota         ports.Support  `json:"quota"`
	NativeSpeedLimit    ports.Support  `json:"speed_limit"`
	MaxSessions         ports.Support  `json:"max_sessions"`
	UserMutation        ports.Mutation `json:"user_mutation"`
	ListenerMutation    ports.Mutation `json:"listener_mutation"`
	HotReload           bool           `json:"hot_reload"`
	TLS                 bool           `json:"tls"`
	Reality             bool           `json:"reality"`
	Vision              bool           `json:"vision"`
	SupportedFlows      []string       `json:"supported_flows,omitempty"`
	SupportedTransports []string       `json:"supported_transports,omitempty"`
}
// QualifiedClient preserves a declared client/version compatibility pair.
// Evidence is a public informational string, empty when none is published.
type QualifiedClient struct {
	Client   string `json:"client"`
	Version  string `json:"version"`
	Evidence string `json:"evidence"`
}
type Capability struct {
	Roles                 ports.Roles            `json:"roles"`
	Protocol              string                 `json:"protocol"`
	WireVersion           string                 `json:"wire_version"`
	FeatureProfile        string                 `json:"feature_profile"`
	Availability          ports.Availability     `json:"availability"`
	Qualification         string                 `json:"qualification"`
	Features              Features               `json:"features"`
	QualifiedClients      []QualifiedClient      `json:"qualified_clients"`
	EngineImplementations []EngineImplementation `json:"engine_implementations"`
}
type EngineImplementation struct {
	Roles              ports.Roles        `json:"roles"`
	Engine             string             `json:"engine"`
	Availability       ports.Availability `json:"availability"`
	RuntimeImplemented bool               `json:"runtime_implemented"`
	Features           Features           `json:"features"`
	NodeStatus         ports.EngineStatus `json:"node_status"`
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
	underlay    *underlay.Factory
	client      *clientState
	runtime     *runtimeState
	repo        ports.Repository
	protocols   *registry.Protocols
	engines     *registry.Engines
	exporters   *registry.Exporters
	instance    identity.ID
	build       version.Info
	fingerprint string
}

func New(repo ports.Repository, p *registry.Protocols, e *registry.Engines, x *registry.Exporters, build version.Info) (*Service, error) {
	return NewWithUnderlay(repo, p, e, x, build, underlay.New())
}
func NewWithUnderlay(repo ports.Repository, p *registry.Protocols, e *registry.Engines, x *registry.Exporters, build version.Info, f *underlay.Factory) (*Service, error) {
	if _, err := f.New(underlay.Scope{Purpose: underlay.ServerTarget}); err != nil {
		return nil, err
	}
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
	return &Service{underlay: f, repo: repo, protocols: p, engines: e, exporters: x, instance: id, build: build, fingerprint: hex.EncodeToString(sum[:])}, nil
}

func (s *Service) System(ctx context.Context) (System, error) {
	providers, err := s.ProviderDiagnostics(ctx)
	if err != nil {
		providers.LastError = "provider_committed_state_unavailable"
	}
	servers := []ServerRuntimeSummary{}
	var clientStatus *clientruntime.Status
	state, err := s.repo.State(ctx)
	if err != nil {
		return System{}, err
	}
	health := "degraded"
	reasons := []string{"foundation_only_runtime_not_implemented"}
	if s.runtime != nil {
		health = "healthy"
		reasons = []string{}
		page, e := s.Inbounds(ctx)
		if e != nil {
			return System{}, e
		}
		for _, i := range page.Items {
			servers = append(servers, ServerRuntimeSummary{ID: i.Inbound.ID, Protocol: i.Inbound.Protocol, Engine: i.Inbound.Engine, Health: i.Health})
			if i.Health != "healthy" {
				health = "degraded"
				reasons = append(reasons, "runtime_unhealthy")
			}
		}
	}
	if s.client != nil {
		status, err := s.ClientStatus(ctx)
		if err != nil {
			return System{}, err
		}
		clientStatus = &status
		if status.Health == "degraded" {
			health = "degraded"
			reasons = append(reasons, "client_runtime_unhealthy")
		}
	}
	if state.PendingTransactions > 0 {
		health = "recovery_required"
		reasons = append(reasons, "pending_transaction_requires_review")
	}
	return System{Providers: providers, ServerRuntimes: servers, ClientRuntime: clientStatus, NodeID: state.NodeID, InstanceID: s.instance, Version: s.build, ConfigSchema: version.ConfigSchema, DBSchema: state.Schema, ProtocolABI: version.ProtocolABI, CommittedRevision: state.Revision, Health: health, Reasons: reasons, Engines: s.engineStatuses(), Foundation: Foundation{DatabaseStatus: "ready", PendingMigrations: state.PendingMigrations, PendingTransactions: state.PendingTransactions, Protocols: len(s.protocols.Keys()), Engines: len(s.engines.Keys()), Exporters: len(s.exporters.Keys())}}, nil
}

func engineStatus(e ports.Engine) ports.EngineStatus {
	m := e.Metadata()
	return ports.EngineStatus{Engine: m.ID, Available: m.Availability == ports.Compiled && m.RuntimeImplemented}
}
func (s *Service) engineStatuses() []ports.EngineStatus {
	result := []ports.EngineStatus{}
	for _, id := range s.engines.Keys() {
		e, _ := s.engines.Get(id)
		result = append(result, engineStatus(e))
	}
	return result
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
			clients = append(clients, QualifiedClient{q.Client, q.Version, q.Evidence})
		}
		page.Items = append(page.Items, Capability{Roles: m.Roles, Protocol: key.Protocol, WireVersion: key.WireVersion, FeatureProfile: key.FeatureProfile, Availability: m.Availability, Qualification: m.Qualification, Features: Features{Implementation: implementation(m.Qualification), TCP: c.Transport.TCP, UDPTransport: c.Transport.UDPTransport, UDPPayload: c.Transport.UDPPayload, IPv4: c.Transport.IPv4, IPv6: c.Transport.IPv6, DomainEndpoint: c.Transport.DomainEndpoint, NativeMultiUser: c.Identity.MultiUserNative, NativeStats: c.Identity.NativeStats, PerUserStats: c.Identity.PerUserStats, HotUserUpdate: c.Mutation.Users == ports.Hot, AttributedPayload: c.Identity.AttributedPayload, NativeQuota: c.Policy.Quota, NativeSpeedLimit: c.Policy.SpeedLimit, MaxSessions: c.Policy.MaxSessions, UserMutation: c.Mutation.Users, ListenerMutation: c.Mutation.Listener, HotReload: c.Mutation.HotReload, TLS: c.Security.TLS, Reality: c.Security.Reality, Vision: c.Security.Vision, SupportedFlows: c.Security.Flows, SupportedTransports: c.Transport.Kinds}, QualifiedClients: clients})
		item := &page.Items[len(page.Items)-1]
		item.EngineImplementations = []EngineImplementation{}
		for _, engine := range s.engines.Implementations(key.Protocol) {
			adapter, _ := s.engines.Get(engine.ID)
			cap := ports.EffectiveCapabilities(p.Capabilities(ports.CapabilityContext{Engine: engine.ID, Platform: s.build.Platform}), adapter.Capabilities())
			availability := engine.Availability
			if m.Availability != ports.Compiled {
				availability = m.Availability
			}
			features := Features{Implementation: "placeholder", NativeStats: ports.Unsupported, AttributedPayload: ports.Unsupported, NativeQuota: ports.Unsupported, NativeSpeedLimit: ports.Unsupported, MaxSessions: ports.Unsupported, UserMutation: ports.MutationUnavailable, ListenerMutation: ports.MutationUnavailable}
			if availability == ports.Compiled && engine.RuntimeImplemented {
				features = Features{Implementation: engine.ID, TCP: cap.Transport.TCP, UDPTransport: cap.Transport.UDPTransport, UDPPayload: cap.Transport.UDPPayload, IPv4: cap.Transport.IPv4, IPv6: cap.Transport.IPv6, DomainEndpoint: cap.Transport.DomainEndpoint, NativeMultiUser: cap.Identity.MultiUserNative, NativeStats: cap.Identity.NativeStats, PerUserStats: cap.Identity.PerUserStats, HotUserUpdate: cap.Mutation.Users == ports.Hot, AttributedPayload: cap.Identity.AttributedPayload, NativeQuota: cap.Policy.Quota, NativeSpeedLimit: cap.Policy.SpeedLimit, MaxSessions: cap.Policy.MaxSessions, UserMutation: cap.Mutation.Users, ListenerMutation: cap.Mutation.Listener, HotReload: cap.Mutation.HotReload, TLS: cap.Security.TLS, Reality: cap.Security.Reality, Vision: cap.Security.Vision, SupportedFlows: cap.Security.Flows, SupportedTransports: cap.Transport.Kinds}
			}
			item.EngineImplementations = append(item.EngineImplementations, EngineImplementation{Roles: ports.Roles{Inbound: m.Roles.Inbound && engine.Roles.Inbound, Outbound: m.Roles.Outbound && engine.Roles.Outbound}, Engine: engine.ID, Availability: availability, RuntimeImplemented: engine.RuntimeImplemented && availability == ports.Compiled, Features: features, NodeStatus: engineStatus(adapter)})
		}
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
	if s.runtime != nil {
		return identity.Transaction{}, identity.Err(identity.NotImplemented, "live account mutation requires runtime coordination")
	}
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
	d := Doctor{Version: s.build, Checks: []Check{{"platform", "pass", s.build.Platform}, {"storage", "pass", "committed SQLite available"}, {"db_schema", "pass", strconv.Itoa(state.Schema)}, {"migrations", "pass", strconv.Itoa(state.PendingMigrations) + " pending"}, {"transactions", "info", strconv.Itoa(state.PendingTransactions) + " pending"}, {"protocol_registry", "pass", strconv.Itoa(len(s.protocols.Keys())) + " registered entries"}, {"engine_registry", "pass", strconv.Itoa(len(s.engines.Keys())) + " engine entries"}, {"exporter_registry", "pass", strconv.Itoa(len(s.exporters.Keys())) + " registered entries"}, {"api_transport", "pass", transport}}}
	for _, engine := range s.engineStatuses() {
		status := "unavailable"
		if engine.Available {
			status = "pass"
		}
		d.Checks = append(d.Checks, Check{"engine_" + engine.Engine, status, "compiled runtime"})
	}
	system, err := s.System(ctx)
	if err != nil {
		return Doctor{}, err
	}
	runtimeStatus := "info"
	if s.runtime != nil {
		runtimeStatus = "pass"
		if system.Health != "healthy" {
			runtimeStatus = "fail"
		}
	}
	d.Checks = append(d.Checks, Check{"runtime_consistency", runtimeStatus, "passive committed state and runtime health comparison"})
	if s.runtime != nil {
		s.runtime.mu.Lock()
		inbounds, validationErr := s.runtime.repo.Inbounds(ctx)
		if validationErr == nil {
			for _, in := range inbounds {
				intent, err := s.projection(ctx, in, state.Revision)
				if err == nil {
					module, e := s.protocols.Get(in.Protocol)
					err = e
					if err == nil {
						_, err = module.BuildRuntime(ctx, intent)
					}
				}
				status := "pass"
				if err != nil {
					status = "fail"
				}
				d.Checks = append(d.Checks, Check{"inbound_" + string(in.ID) + "_validation", status, "protocol settings, credentials and account-binding references"})
			}
		}
		s.runtime.mu.Unlock()
		if validationErr != nil {
			return Doctor{}, validationErr
		}
	}
	providerStatus := "pass"
	if system.Providers.Degraded > 0 || system.Providers.LastError != "" {
		providerStatus = "fail"
	}
	d.Checks = append(d.Checks, Check{"provider_health", providerStatus, strconv.Itoa(system.Providers.Degraded) + " degraded; " + strconv.Itoa(system.Providers.StaleNodes) + " stale nodes"})
	return d, nil
}

func implementation(q string) string {
	if q == "experimental" {
		return "native"
	}
	return "placeholder"
}
