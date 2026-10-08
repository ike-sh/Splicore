package application

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/nodeimport"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/trojan"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/vmess"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

type NodeExportRequest struct {
	IDs           []identity.ID `json:"ids,omitempty"`
	ProviderID    identity.ID   `json:"provider_id,omitempty"`
	All           bool          `json:"all,omitempty"`
	Format        string        `json:"format"`
	ClientVersion string        `json:"client_version,omitempty"`
	RevealSecrets bool          `json:"reveal_secrets"`
}
type NodeExport struct {
	Content         string             `json:"content"`
	ContainsSecrets bool               `json:"contains_secrets"`
	Details         []NodeExportDetail `json:"details,omitempty"`
}
type NodeExportDetail struct {
	NodeID      identity.ID             `json:"node_id"`
	Description ports.ExportDescription `json:"description"`
}

func (NodeExport) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("NodeExport{[REDACTED]}")) }
func credentialInput(c access.Credential) nodeimport.Credential {
	input := nodeimport.Credential{Kind: c.Kind}
	switch p := c.Payload.(type) {
	case access.PSKPayload:
		input.Value = p.Key.Reveal()
	case access.PasswordPayload:
		input.Value = p.Password.Reveal()
	case access.UUIDPayload:
		input.Value = p.UUID.Reveal()
	case access.UUIDPasswordPayload:
		b, _ := json.Marshal(map[string]string{"uuid": p.UUID.Reveal(), "password": p.Password.Reveal()})
		input.Value = string(b)
	case access.UsernamePasswordPayload:
		b, _ := json.Marshal(map[string]string{"username": p.Username.Reveal(), "password": p.Password.Reveal()})
		input.Value = string(b)
	}
	return input
}
func (s *Service) ExportNodes(ctx context.Context, r NodeExportRequest) (NodeExport, error) {
	if s.client == nil || !r.RevealSecrets || len(r.IDs) > 128 {
		return NodeExport{}, managementInvalid()
	}
	count := 0
	if len(r.IDs) > 0 {
		count++
	}
	if r.ProviderID != "" {
		count++
		if r.ProviderID.Validate() != nil {
			return NodeExport{}, managementInvalid()
		}
	}
	if r.All {
		count++
	}
	if count != 1 {
		return NodeExport{}, managementInvalid()
	}
	c := s.client
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return NodeExport{}, identity.Err(identity.Unavailable, "client runtime closed")
	}
	state, e := c.repo.ClientState(ctx)
	if e != nil {
		return NodeExport{}, e
	}
	requested := map[identity.ID]bool{}
	for _, id := range r.IDs {
		if id.Validate() != nil || requested[id] {
			return NodeExport{}, managementInvalid()
		}
		requested[id] = true
	}
	canonical := nodeimport.Document{Schema: 1, Nodes: []nodeimport.Candidate{}}
	uris := []string{}
	external := []any{}
	details := []NodeExportDetail{}
	for _, n := range state.Nodes {
		if !r.All && !requested[n.ID] && (r.ProviderID == "" || n.Provenance.ProviderID != r.ProviderID) {
			continue
		}
		cred, e := c.repo.RevealCredential(ctx, n.CredentialID)
		if e != nil {
			return NodeExport{}, e
		}
		if cred.OwnerNodeID == nil || *cred.OwnerNodeID != n.ID {
			return NodeExport{}, managementInvalid()
		}
		delete(requested, n.ID)
		if r.Format == "canonical" {
			candidate := nodeimport.Candidate{Node: n, Credential: credentialInput(cred)}
			candidate.Node.ID = ""
			candidate.Node.CredentialID = ""
			candidate.Node.Provenance.Origin = ""
			candidate.Node.Provenance.ProviderID = ""
			candidate.Node.Provenance.Key = ""
			candidate.Node.State = ""
			canonical.Nodes = append(canonical.Nodes, candidate)
			continue
		}
		profile := clientprofile.Profile{ID: n.ID, Schema: 1, Protocol: n.Protocol, Endpoint: n.Endpoint, Credentials: cred.Payload, TLS: n.Security.TLS, Transport: clientprofile.Transport{Kind: n.Transport.Kind}, UDPPayload: true, Options: access.Settings{Schema: 1, Data: slices.Clone(n.Options.Data)}, Metadata: n.Metadata}
		if n.Protocol.Protocol == "socks5" || n.Protocol.Protocol == "http" {
			profile.Metadata = identity.Metadata{}
			for k, v := range n.Metadata {
				profile.Metadata[k] = v
			}
			profile.Metadata["display_name"] = n.Name
		}
		if n.Protocol == trojan.Key() {
			options, err := trojan.DecodeClientOptions(n.Options.Data)
			if err != nil {
				return NodeExport{}, err
			}
			profile.UDPPayload = options.UDP
			profile.Metadata = identity.Metadata{}
			for k, v := range n.Metadata {
				profile.Metadata[k] = v
			}
			profile.Metadata["display_name"] = n.Name
		}
		if n.Protocol == vmess.Key() {
			options, err := vmess.DecodeClientOptions(n.Options.Data)
			if err != nil {
				return NodeExport{}, err
			}
			profile.UDPPayload = options.UDP
			profile.Metadata = identity.Metadata{}
			for k, v := range n.Metadata {
				profile.Metadata[k] = v
			}
			profile.Metadata["display_name"] = n.Name
		}
		if r.Format == "uri" && n.Protocol.Protocol == "hysteria2" {
			if n.Security.TLS.Trust != "system" {
				return NodeExport{}, identity.Err(identity.UnsupportedExport, "URI cannot represent trust")
			}
			u := url.URL{Scheme: "hysteria2", User: url.User(cred.Payload.(access.PasswordPayload).Password.Reveal()), Host: net.JoinHostPort(n.Endpoint.Host, strconv.Itoa(int(n.Endpoint.Port))), RawQuery: url.Values{"sni": {n.Security.TLS.ServerName}}.Encode(), Fragment: n.Name}
			uris = append(uris, u.String())
			continue
		}
		exporter, e := s.exporters.Get(ports.Format(r.Format))
		if e != nil {
			return NodeExport{}, e
		}
		b, e := exporter.Export(ctx, profile, ports.ExportTarget{Format: ports.Format(r.Format), ClientVersion: r.ClientVersion})
		if e != nil {
			return NodeExport{}, e
		}
		if d, ok := exporter.(ports.ExportDescriber); ok {
			description, err := d.Describe(profile)
			if err != nil {
				return NodeExport{}, err
			}
			details = append(details, NodeExportDetail{NodeID: n.ID, Description: description})
		}
		if r.Format == "uri" {
			uris = append(uris, string(b))
		} else {
			var value map[string]any
			if json.Unmarshal(b, &value) != nil {
				return NodeExport{}, managementInvalid()
			}
			if r.Format == "mihomo" {
				a, ok := value["proxies"].([]any)
				if ok {
					external = append(external, a...)
				} else if value["type"] != nil {
					external = append(external, value)
				} else {
					return NodeExport{}, managementInvalid()
				}
			} else if r.Format == "mieru" {
				a, ok := value["profiles"].([]any)
				if !ok {
					return NodeExport{}, managementInvalid()
				}
				external = append(external, a...)
			} else {
				external = append(external, value)
			}
		}
	}
	if len(requested) > 0 {
		return NodeExport{}, identity.Err(identity.NotFound, "export node not found")
	}
	var b []byte
	switch r.Format {
	case "canonical":
		b, e = json.Marshal(canonical)
	case "uri":
		b = []byte(strings.Join(uris, "\n"))
	case "mihomo":
		b, e = json.Marshal(map[string]any{"proxies": external})
	case "sing-box":
		b, e = json.Marshal(map[string]any{"outbounds": external})
	case "mieru":
		value := map[string]any{"profiles": external}
		if len(external) > 0 {
			value["activeProfile"] = external[0].(map[string]any)["profileName"]
		}
		b, e = json.Marshal(value)
	default:
		return NodeExport{}, identity.Err(identity.UnsupportedExport, "unsupported node export format")
	}
	if e != nil {
		return NodeExport{}, managementInvalid()
	}
	return NodeExport{Content: string(b), ContainsSecrets: true, Details: details}, nil
}
