// Package ports owns implementation boundaries; it imports neither SQL nor HTTP.
package ports

import (
	"context"

	"github.com/sagernet/sing-box/internal/splicore/clientprofile"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/policy"
)

type Availability string

const (
	Compiled            Availability = "compiled"
	NotCompiled         Availability = "not_compiled"
	UnsupportedPlatform Availability = "unsupported_platform"
)

type Support string

const (
	Unsupported    Support = "unsupported"
	AdapterPending Support = "adapter_pending"
	Native         Support = "native"
)

type Mutation string

const (
	Restart             Mutation = "restart"
	Hot                 Mutation = "hot"
	MutationUnavailable Mutation = "unavailable"
)

type Format string

const (
	Mihomo  Format = "mihomo"
	SingBox Format = "sing-box"
	Surge   Format = "surge"
	URI     Format = "uri"
	JSON    Format = "json"
	Xray    Format = "xray"
)

type TransportCapabilities struct {
	Kinds          []string
	TCP            bool
	UDPTransport   bool
	UDPPayload     bool
	IPv4           bool
	IPv6           bool
	DomainEndpoint bool
}
type IdentityCapabilities struct {
	MultiUserNative   bool
	PerUserStats      bool
	AttributedPayload Support
	NativeStats       Support
	StatsUnits        string
}
type PolicyCapabilities struct {
	Quota       Support
	SpeedLimit  Support
	MaxSessions Support
}
type MutationCapabilities struct {
	Users     Mutation
	Listener  Mutation
	HotReload bool
}
type SecurityCapabilities struct {
	TLS     bool
	Reality bool
	Vision  bool
	Flows   []string
}
type ClientCompatibility struct {
	Format   Format
	Client   string
	Version  string
	Evidence string
}
type Capabilities struct {
	Transport      TransportCapabilities
	Identity       IdentityCapabilities
	Policy         PolicyCapabilities
	Mutation       MutationCapabilities
	Security       SecurityCapabilities
	Clients        []ClientCompatibility
	EngineFeatures []EngineFeature
}
type ProtocolMetadata struct {
	Key             access.ProtocolKey
	ABI             int
	CredentialKinds []access.CredentialKind
	Availability    Availability
	Qualification   string
	Provenance      string
}
type CapabilityContext struct {
	Engine   string
	Platform string
}
type RuntimeIntent struct {
	Inbound           access.Inbound
	Bindings          []access.Binding
	Credentials       []access.Credential
	ServerCredentials []access.Credential
	Revision          identity.Revision
}
type AuthorizedBinding struct {
	Binding                 access.Binding
	Inbound                 access.Inbound
	Credential              access.Credential
	ClientSharedCredentials []access.Credential
}
type Protocol interface {
	Metadata() ProtocolMetadata
	Capabilities(CapabilityContext) Capabilities
	ValidateInbound(access.Inbound) error
	ValidateCredential(access.Credential) error
	BuildRuntime(context.Context, RuntimeIntent) (RuntimeIntent, error)
	BuildClientProfile(context.Context, AuthorizedBinding) (clientprofile.Profile, error)
}

// Engine compilers own concrete runtime options. Preparation and handles are deferred.
type EngineMetadata struct {
	ID                 string
	Availability       Availability
	RuntimeImplemented bool
	ABI                int
	Protocols          []string
}
type (
	PreparedRuntime interface{ Close(context.Context) error }
	Engine          interface {
		Metadata() EngineMetadata
		Capabilities() Capabilities
		Supports(RuntimeIntent) error
		Compile(context.Context, RuntimeIntent) (PreparedRuntime, error)
	}
)

type ExportTarget struct {
	Format        Format
	ClientVersion string
}
type Exporter interface {
	Format() Format
	Export(context.Context, clientprofile.Profile, ExportTarget) ([]byte, error)
}

type State struct {
	NodeID              identity.ID
	Revision            identity.Revision
	Schema              int
	PendingMigrations   int
	PendingTransactions int
}
type Reader interface {
	State(context.Context) (State, error)
	Account(context.Context, identity.ID) (access.Account, error)
}

// Writer methods run within one short domain transaction. Callbacks must not do I/O.
type Writer interface {
	CreateAccount(access.Account) error
	UpdateAccount(access.Account, identity.Revision) error
	CreateInbound(access.Inbound) error
	CreateCredential(access.Credential) error
	CreateBinding(access.Binding) error
	CreatePolicy(policy.TrafficPolicy) error
}
type Repository interface {
	Reader
	Transact(context.Context, identity.Revision, identity.Actor, func(Writer) error) (identity.Transaction, error)
}

// Cipher uses owner-bound associated data. Implementations never store keys in the DB.
type Cipher interface {
	KeyID() string
	Seal([]byte, []byte) ([]byte, error)
	Open([]byte, []byte) ([]byte, error)
}
