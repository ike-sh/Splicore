// Package clientprofile defines sensitive client projections, never server configuration.
package clientprofile

import (
	"fmt"

	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
)

type TLS struct {
	Enabled          bool     `json:"enabled"`
	ServerName       string   `json:"server_name,omitempty"`
	ALPN             []string `json:"alpn,omitempty"`
	Trust            string   `json:"trust,omitempty"`
	CACertificate    string   `json:"ca_certificate,omitempty"`
	RealityPublicKey string   `json:"reality_public_key,omitempty"`
	RealityShortID   string   `json:"reality_short_id,omitempty"`
}
type Transport struct {
	Kind string `json:"kind"`
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`
}
type Profile struct {
	ID          identity.ID        `json:"id"`
	Schema      int                `json:"schema_version"`
	Protocol    access.ProtocolKey `json:"protocol"`
	Endpoint    access.Endpoint    `json:"endpoint"`
	Credentials access.Payload     `json:"-"`
	TLS         TLS                `json:"tls"`
	Transport   Transport          `json:"transport"`
	UDPPayload  bool               `json:"udp_payload"`
	Options     access.Settings    `json:"options"`
	Metadata    identity.Metadata  `json:"metadata"`
}

func (p Profile) Format(s fmt.State, verb rune) {
	_, _ = s.Write([]byte("ClientProfile{" + secret.Redacted + "}"))
}

func (p Profile) Validate() error {
	if err := p.ID.Validate(); err != nil {
		return err
	}
	if p.Schema != 1 || p.Credentials == nil {
		return identity.Err(identity.Invalid, "invalid client profile")
	}
	if err := access.ValidatePayload(p.Credentials); err != nil {
		return err
	}
	if err := p.Protocol.Validate(); err != nil {
		return err
	}
	if err := p.Endpoint.Validate(); err != nil {
		return err
	}
	if err := p.Metadata.Validate(); err != nil {
		return err
	}
	return p.Options.Validate()
}
