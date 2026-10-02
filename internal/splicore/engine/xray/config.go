// Package xray translates canonical intent and owns an external Xray child.
// Xray source, wire framing and cryptography remain outside this package.
package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	v "github.com/sagernet/sing-box/internal/splicore/protocol/vless"
	"github.com/sagernet/sing-box/internal/splicore/tlsconfig"
)

type configuration struct {
	Log struct {
		Level string `json:"loglevel"`
	} `json:"log"`
	Inbounds  []inboundConfig  `json:"inbounds"`
	Outbounds []outboundConfig `json:"outbounds"`
}

func (configuration) Format(f fmt.State, verb rune) { _, _ = f.Write([]byte("XrayConfig{[REDACTED]}")) }

type inboundConfig struct {
	Tag      string       `json:"tag"`
	Listen   string       `json:"listen"`
	Port     uint16       `json:"port"`
	Protocol string       `json:"protocol"`
	Settings userConfig   `json:"settings"`
	Stream   streamConfig `json:"streamSettings"`
}
type userConfig struct {
	Clients    []client `json:"clients"`
	Decryption string   `json:"decryption"`
}
type client struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}
type streamConfig struct {
	Network  string         `json:"network"`
	Security string         `json:"security"`
	Reality  *realityConfig `json:"realitySettings,omitempty"`
	TLS      *tlsConfig     `json:"tlsSettings,omitempty"`
}
type realityConfig struct {
	Target      string   `json:"target"`
	ServerNames []string `json:"serverNames"`
	PrivateKey  string   `json:"privateKey"`
	ShortIDs    []string `json:"shortIds"`
}
type tlsConfig struct {
	ServerName   string              `json:"serverName"`
	MinVersion   string              `json:"minVersion"`
	Certificates []certificateConfig `json:"certificates"`
}
type certificateConfig struct {
	Certificate []string `json:"certificate"`
	Key         []string `json:"key"`
}
type outboundConfig struct {
	Protocol string `json:"protocol"`
	Tag      string `json:"tag"`
}

func validateIntent(in ports.RuntimeIntent) (v.Settings, error) {
	// This gate precedes binary checks, file access and child construction.
	s, err := v.Decode(in.Inbound.Settings.Data)
	if err != nil {
		return s, err
	}
	if in.Inbound.Engine != "xray" {
		return s, identity.Err(identity.Invalid, "engine binding mismatch")
	}
	_, err = (v.Module{Security: s.Security}).BuildRuntime(context.Background(), in)
	return s, err
}
func render(in ports.RuntimeIntent, endpoint access.Endpoint) ([]byte, error) {
	s, err := validateIntent(in)
	if err != nil {
		return nil, err
	}
	if endpoint.Validate() != nil || endpoint.Host != "127.0.0.1" {
		return nil, identity.Err(identity.Invalid, "invalid private child endpoint")
	}
	node := inboundConfig{Tag: "managed-vless", Listen: endpoint.Host, Port: endpoint.Port, Protocol: "vless",
		Settings: userConfig{Clients: []client{}, Decryption: "none"}, Stream: streamConfig{Network: "raw", Security: string(s.Security)}}
	for n, b := range in.Bindings {
		node.Settings.Clients = append(node.Settings.Clients, client{ID: in.Credentials[n].Payload.(access.UUIDPayload).UUID.Reveal(), Email: string(b.ID)})
	}
	if s.Security == v.Reality {
		ids := make([]string, len(s.Reality.ShortIDs))
		for n, id := range s.Reality.ShortIDs {
			ids[n] = string(id)
		}
		node.Stream.Reality = &realityConfig{Target: net.JoinHostPort(s.Reality.Target.Host, strconv.Itoa(int(s.Reality.Target.Port))),
			ServerNames: []string{s.Reality.ServerName}, PrivateKey: in.ServerCredentials[0].Payload.(access.PrivateKeyPayload).Material.Reveal(), ShortIDs: ids}
	}
	if s.Security == v.TLS {
		cert, key, err := tlsconfig.Snapshot(*s.TLS)
		if err != nil {
			return nil, err
		}
		defer clear(key)
		node.Stream.TLS = &tlsConfig{ServerName: s.TLS.ServerName, MinVersion: "1.3", Certificates: []certificateConfig{{Certificate: strings.Split(string(cert), "\n"), Key: strings.Split(string(key), "\n")}}}
	}
	c := configuration{Inbounds: []inboundConfig{node}, Outbounds: []outboundConfig{{Protocol: "freedom", Tag: "direct"}}}
	c.Log.Level = "none"
	return json.Marshal(c)
}
