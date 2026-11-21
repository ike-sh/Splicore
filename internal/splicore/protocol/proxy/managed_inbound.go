package proxy

import (
	"context"
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/credential"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/creation"
)

// SOCKS5Inbound owns managed, authenticated SOCKS5 server intent.
// Upstream SOCKS5 nodes keep their existing, independent options.
type SOCKS5Inbound struct{ managedInbound }

// HTTPInbound provides managed, authenticated HTTP/1.1 server intent.
func HTTPInbound() managedInbound { return managedInbound{http: true} }

type managedInbound struct{ http bool }

func (m managedInbound) key() access.ProtocolKey {
	if m.http {
		return Key("http")
	}
	return Key("socks5")
}

func (m managedInbound) invalid() error {
	if m.http {
		return identity.Err(identity.Invalid, "invalid managed HTTP proxy settings or credentials")
	}
	return identity.Err(identity.Invalid, "invalid managed SOCKS5 settings or credentials")
}

func IsManagedInbound(key access.ProtocolKey) bool {
	return key == Key("socks5") || key == Key("http")
}

type managedServerOptions struct {
	Auth                 bool            `json:"auth"`
	UDP                  bool            `json:"udp,omitempty"`
	UDPRelay             *SOCKS5UDPRelay `json:"udp_relay,omitempty"`
	AllowCleartextRemote bool            `json:"allow_cleartext_remote,omitempty"`
}

// SOCKS5UDPRelay configures the ingress socket and the address sent in BND.ADDR.
// The advertised port is always the actual bound port.
type SOCKS5UDPRelay struct {
	Listen    string `json:"listen,omitempty"`
	Advertise string `json:"advertise,omitempty"`
	PortMin   uint16 `json:"port_min,omitempty"`
	PortMax   uint16 `json:"port_max,omitempty"`
}

func (r SOCKS5UDPRelay) withDefaults(listener netip.Addr) SOCKS5UDPRelay {
	if r.Listen == "" {
		r.Listen = listener.Unmap().String()
	}
	if r.Advertise == "" {
		r.Advertise = r.Listen
	}
	return r
}

func (r SOCKS5UDPRelay) valid(listener netip.Addr, allowRemote bool) bool {
	r = r.withDefaults(listener)
	bind, err := netip.ParseAddr(r.Listen)
	if err != nil || bind.Zone() != "" || bind.IsMulticast() || bind != bind.Unmap() ||
		bind.Is4() != listener.Unmap().Is4() || r.PortMin == 0 && r.PortMax != 0 ||
		r.PortMin > r.PortMax || int(r.PortMax)-int(r.PortMin) >= 1024 {
		return false
	}
	if (access.Endpoint{Host: r.Advertise, Port: 1}).Validate() != nil {
		return false
	}
	if advertised, err := netip.ParseAddr(r.Advertise); err == nil &&
		(advertised.IsUnspecified() || advertised.IsMulticast() || advertised.Zone() != "" ||
			advertised.Unmap().Is4() != bind.Is4() || advertised.IsLoopback() != bind.IsLoopback()) {
		return false
	}
	if !bind.IsLoopback() {
		return allowRemote && !listener.Unmap().IsLoopback() && r.PortMin != 0
	}
	return listener.Unmap().IsLoopback()
}

func (SOCKS5Inbound) UDPRelay(in access.Inbound) (SOCKS5UDPRelay, bool, error) {
	if len(in.Listeners) != 1 {
		return SOCKS5UDPRelay{}, false, (managedInbound{}).invalid()
	}
	listener := in.Listeners[0].Endpoint
	options, err := (managedInbound{}).serverSettings(in.Settings.Data, listener)
	if err != nil || !options.UDP {
		return SOCKS5UDPRelay{}, false, err
	}
	return options.UDPRelay.withDefaults(netip.MustParseAddr(listener.Host)), true, nil
}

var managedUsername = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

func (m managedInbound) serverSettings(data json.RawMessage, listener access.Endpoint) (managedServerOptions, error) {
	var options managedServerOptions
	ip, err := netip.ParseAddr(listener.Host)
	if len(data) > 1024 || creation.Decode(data, &options) != nil || !options.Auth ||
		err != nil || ip.Zone() != "" || !ip.Unmap().IsLoopback() && !options.AllowCleartextRemote {
		return options, m.invalid()
	}
	if !options.UDP {
		if options.UDPRelay != nil {
			return options, m.invalid()
		}
		return options, nil
	}
	if options.UDPRelay == nil {
		options.UDPRelay = &SOCKS5UDPRelay{}
	}
	if m.http || !options.UDPRelay.valid(ip, options.AllowCleartextRemote) ||
		!ip.Unmap().IsLoopback() && options.UDPRelay.Advertise == "" {
		return options, m.invalid()
	}
	return options, nil
}

func validManagedPassword(username string, password secret.Value) bool {
	value := password.Reveal()
	if len(value) < 16 || credential.ValidatePassword(password) != nil || strings.EqualFold(username, value) {
		return false
	}
	var seen [128]bool
	distinct := 0
	for i := range len(value) {
		c := value[i]
		if c < 33 || c > 126 {
			return false
		}
		if !seen[c] {
			seen[c] = true
			distinct++
		}
	}
	return distinct >= 8
}

func (m managedInbound) Metadata() ports.ProtocolMetadata {
	provenance := "native RFC 1928 CONNECT and optional UDP ASSOCIATE with RFC 1929 username/password"
	if m.http {
		provenance = "native HTTP/1.1 CONNECT and absolute-form forwarding with Basic proxy authentication"
	}
	return ports.ProtocolMetadata{Key: m.key(), Roles: ports.Roles{Inbound: true, Outbound: true},
		ABI: 1, CredentialKinds: []access.CredentialKind{access.UsernamePassword}, Availability: ports.Compiled,
		Provenance: provenance}
}

func (m managedInbound) Capabilities(ports.CapabilityContext) ports.Capabilities {
	capabilities := ports.Capabilities{
		Transport: ports.TransportCapabilities{Kinds: []string{"tcp"}, TCP: true, IPv4: true, IPv6: true, DomainEndpoint: true},
		Identity:  ports.IdentityCapabilities{MultiUserNative: true, PerUserStats: true, AttributedPayload: ports.Native, NativeStats: ports.Native},
		Policy:    ports.PolicyCapabilities{Quota: ports.Unsupported, SpeedLimit: ports.Unsupported, MaxSessions: ports.Unsupported},
		Mutation:  ports.MutationCapabilities{Users: ports.Restart, Listener: ports.MutationUnavailable},
	}
	if !m.http {
		capabilities.Transport.Kinds = append(capabilities.Transport.Kinds, "udp")
		capabilities.Transport.UDPTransport = true
		capabilities.Transport.UDPPayload = true
		capabilities.Clients = []ports.ClientCompatibility{
			{Format: ports.Mihomo, Client: "mihomo", Version: "1.19.32"},
			{Format: ports.SingBox, Client: "sing-box", Version: "1.14.2"},
		}
	}
	return capabilities
}

func (m managedInbound) ValidateInbound(in access.Inbound) error {
	if in.Validate() != nil || in.Protocol != m.key() || in.Engine != "native" ||
		len(in.Listeners) != 1 || in.Listeners[0].Transport != "tcp" || len(in.DisplayEndpoints) != 1 {
		return m.invalid()
	}
	if _, err := m.serverSettings(in.Settings.Data, in.Listeners[0].Endpoint); err != nil {
		return err
	}
	if host, err := netip.ParseAddr(in.DisplayEndpoints[0].Endpoint.Host); err == nil && host.IsUnspecified() {
		return m.invalid()
	}
	return nil
}

func (m managedInbound) ValidateCredential(c access.Credential) error {
	pair, ok := c.Payload.(access.UsernamePasswordPayload)
	if !ok || c.Validate() != nil || c.State != "active" || !managedUsername.MatchString(pair.Username.Reveal()) ||
		!validManagedPassword(pair.Username.Reveal(), pair.Password) {
		return m.invalid()
	}
	return nil
}

func (m managedInbound) BuildRuntime(_ context.Context, in ports.RuntimeIntent) (ports.RuntimeIntent, error) {
	if err := m.ValidateInbound(in.Inbound); err != nil {
		return in, err
	}
	if len(in.Bindings) > 16 || len(in.Bindings) != len(in.Credentials) || len(in.ServerCredentials) != 0 {
		return in, m.invalid()
	}
	ids, usernames := map[identity.ID]bool{}, map[string]bool{}
	for index, binding := range in.Bindings {
		c := in.Credentials[index]
		if binding.Validate() != nil || !binding.Enabled || ids[binding.ID] || binding.InboundID != in.Inbound.ID ||
			binding.CredentialID != c.ID || c.OwnerAccountID == nil || *c.OwnerAccountID != binding.AccountID || m.ValidateCredential(c) != nil {
			return in, m.invalid()
		}
		username := c.Payload.(access.UsernamePasswordPayload).Username.Reveal()
		if usernames[username] {
			return in, m.invalid()
		}
		ids[binding.ID], usernames[username] = true, true
	}
	return in, nil
}

func (m managedInbound) BuildClientProfile(ctx context.Context, b ports.AuthorizedBinding) (clientprofile.Profile, error) {
	if _, err := m.BuildRuntime(ctx, ports.RuntimeIntent{Inbound: b.Inbound, Bindings: []access.Binding{b.Binding},
		Credentials: []access.Credential{b.Credential}, ServerCredentials: b.ServerCredentials}); err != nil {
		return clientprofile.Profile{}, err
	}
	server, err := m.serverSettings(b.Inbound.Settings.Data, b.Inbound.Listeners[0].Endpoint)
	if err != nil {
		return clientprofile.Profile{}, err
	}
	options, _ := json.Marshal(Options{Auth: true, UDP: server.UDP})
	profile := clientprofile.Profile{ID: b.Binding.ID, Schema: 1, Protocol: m.key(),
		Endpoint: b.Inbound.DisplayEndpoints[0].Endpoint, Credentials: b.Credential.Payload, UDPPayload: server.UDP,
		Transport: clientprofile.Transport{Kind: "tcp"}, Options: access.Settings{Schema: 1, Data: options},
		Metadata: identity.Metadata{"display_name": b.Inbound.Name}}
	return profile, profile.Validate()
}

// ManagedUser is the same account input for creation and later HTTP enrollment.
type ManagedUser struct {
	Name      string          `json:"account_name"`
	Enabled   json.RawMessage `json:"enabled,omitempty"`
	Username  string          `json:"username"`
	Password  json.RawMessage `json:"password,omitempty"`
	ExpiresAt *time.Time      `json:"expires_at,omitempty"`
}

func (m managedInbound) UserDraft(user ManagedUser) (ports.CreationUser, error) {
	var enabled creation.Flag
	if len(user.Enabled) > 0 && json.Unmarshal(user.Enabled, &enabled) != nil {
		return ports.CreationUser{}, m.invalid()
	}
	password, err := creation.RawField(user.Password)
	value := secret.New(password)
	if err != nil || !identity.Label(user.Name, 128) ||
		user.ExpiresAt != nil && (user.ExpiresAt.IsZero() || user.ExpiresAt.Location() != time.UTC) ||
		!managedUsername.MatchString(user.Username) ||
		(!value.Empty() && !validManagedPassword(user.Username, value)) {
		return ports.CreationUser{}, m.invalid()
	}
	return ports.CreationUser{Name: user.Name, Enabled: creation.Enabled(enabled), AccountEnabled: true,
		Payload: access.UsernamePasswordPayload{Username: secret.New(user.Username), Password: value}, ExpiresAt: user.ExpiresAt}, nil
}

func (m managedInbound) DecodeCreation(data json.RawMessage) (ports.CreationDraft, error) {
	var w struct {
		Schema   int             `json:"schema"`
		Name     string          `json:"name"`
		Listener access.Endpoint `json:"listener"`
		Display  access.Endpoint `json:"display_endpoint"`
		Settings json.RawMessage `json:"settings"`
		Users    []ManagedUser   `json:"users"`
	}
	var draft ports.CreationDraft
	if creation.Decode(data, &w) != nil {
		return draft, m.invalid()
	}
	if w.Listener.Host == "" {
		w.Listener.Host = "127.0.0.1"
	}
	if w.Display == (access.Endpoint{}) {
		w.Display = w.Listener
	}
	options, err := m.serverSettings(w.Settings, w.Listener)
	if err != nil || creation.ValidateEnvelope(w.Schema, w.Name, w.Listener, w.Display, "", len(w.Users)) != nil {
		return draft, m.invalid()
	}
	if host, err := netip.ParseAddr(w.Display.Host); err == nil && host.IsUnspecified() {
		return draft, m.invalid()
	}
	settings, _ := json.Marshal(options)
	draft = ports.CreationDraft{Name: w.Name, Protocol: m.key(), Transport: "tcp",
		Listener: w.Listener, Display: w.Display, Settings: settings}
	names, usernames := map[string]bool{}, map[string]bool{}
	enabled := false
	for _, user := range w.Users {
		account, err := m.UserDraft(user)
		if err != nil || names[user.Name] || usernames[user.Username] {
			return draft, m.invalid()
		}
		names[user.Name], usernames[user.Username] = true, true
		enabled = enabled || account.Enabled && (account.ExpiresAt == nil || time.Now().Before(*account.ExpiresAt))
		draft.Users = append(draft.Users, account)
	}
	if !enabled {
		return draft, m.invalid()
	}
	return draft, nil
}

func (m managedInbound) GenerateCreationCredential(payload access.Payload) (access.Payload, error) {
	pair, ok := payload.(access.UsernamePasswordPayload)
	if !ok || !managedUsername.MatchString(pair.Username.Reveal()) {
		return nil, m.invalid()
	}
	if pair.Password.Empty() {
		password, err := credential.GeneratePassword()
		if err != nil {
			return nil, err
		}
		pair.Password = password
	}
	if !validManagedPassword(pair.Username.Reveal(), pair.Password) {
		return nil, m.invalid()
	}
	return pair, nil
}
