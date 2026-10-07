package nodeimport

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/vmess"
)

func vmessIssue(index int, err error, unsupportedCode string) Issue {
	if kind, code, ok := module.ImportError(err); ok {
		return Issue{index, kind, code}
	}
	var e *identity.Error
	if errors.As(err, &e) && e.Code == identity.UnsupportedExport {
		return Issue{index, "Unsupported", unsupportedCode}
	}
	return Issue{index, "Invalid", "invalid_vmess"}
}

func externalVMess(format string, b []byte) (Candidate, error) {
	var c Candidate
	var n struct {
		Type       string          `json:"type"`
		Name       string          `json:"name"`
		Tag        string          `json:"tag"`
		Server     string          `json:"server"`
		Port       uint16          `json:"port"`
		ServerPort uint16          `json:"server_port"`
		UUID       string          `json:"uuid"`
		AlterID    int             `json:"alter_id"`
		AlterM     int             `json:"alterId"`
		Security   string          `json:"security"`
		Cipher     string          `json:"cipher"`
		Network    string          `json:"network"`
		UDP        *bool           `json:"udp"`
		TLS        json.RawMessage `json:"tls"`
		SNI        string          `json:"sni"`
		ServerName string          `json:"servername"`
		ALPN       []string        `json:"alpn"`
		SkipVerify bool            `json:"skip-cert-verify"`
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(b, &fields)
	allowed := map[string]bool{"type": true, "server": true, "uuid": true, "network": true, "tls": true}
	keys := []string{"tag", "server_port", "alter_id", "security"}
	if format == "mihomo" {
		keys = []string{"name", "port", "alterId", "cipher", "udp", "sni", "servername", "alpn", "skip-cert-verify"}
	}
	for _, key := range keys {
		allowed[key] = true
	}
	for key, v := range fields {
		if !allowed[key] || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return c, unsupported()
		}
	}
	names := make([]string, 0, len(allowed))
	for key := range allowed {
		names = append(names, key)
	}
	if _, err := module.Object(b, names, false); err != nil {
		return c, err
	}
	if format == "mihomo" {
		_, sni := fields["sni"]
		_, servername := fields["servername"]
		if sni && servername {
			return c, module.ConflictingField()
		}
	}
	if jsonstrict.Decode(b, &n) != nil {
		return c, invalid()
	}
	if (access.UUIDPayload{UUID: secret.New(n.UUID)}).Validate() != nil {
		return c, module.InvalidCredential()
	}
	if n.AlterID != 0 || n.AlterM != 0 {
		return c, module.Unsupported("unsupported_legacy_vmess")
	}
	if n.Network != "" && n.Network != "tcp" {
		return c, module.Unsupported("unsupported_transport")
	}
	port, name, security, udp := n.ServerPort, n.Tag, n.Security, n.Network != "tcp"
	if format == "mihomo" {
		port, name, security, udp = n.Port, n.Name, n.Cipher, true
		if n.UDP != nil {
			udp = *n.UDP
		}
	}
	if security == "" {
		security = "auto"
	}
	if _, err := module.Security(security); err != nil {
		return c, err
	}
	s := client.Security{Kind: "none"}
	if len(n.TLS) > 0 {
		if format == "mihomo" {
			var enabled bool
			if json.Unmarshal(n.TLS, &enabled) != nil || n.SkipVerify || n.SNI != "" && n.ServerName != "" {
				return c, unsupported()
			}
			if enabled {
				serverName := n.ServerName + n.SNI
				if serverName == "" {
					serverName = n.Server
				}
				s = client.Security{Kind: "tls", TLS: access.ClientTLS{Enabled: true, ServerName: serverName, Trust: "system", ALPN: n.ALPN}}
			} else if n.SNI != "" || n.ServerName != "" || len(n.ALPN) > 0 {
				return c, unsupported()
			}
		} else {
			var t externalTLS
			if jsonstrict.Decode(n.TLS, &t) != nil || !t.Enabled || t.Insecure || t.Reality != nil || t.UTLS != nil {
				return c, unsupported()
			}
			// encoding/json otherwise folds field names. Reject aliases such
			// as insecure/Insecure before their conflicting values can collapse.
			var fields map[string]json.RawMessage
			if json.Unmarshal(n.TLS, &fields) != nil {
				return c, invalid()
			}
			for key, value := range fields {
				switch key {
				case "enabled", "insecure", "server_name":
					if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
						return c, unsupported()
					}
				case "alpn", "certificate": // null arrays mean the empty optional list
				default:
					return c, unsupported()
				}
			}
			serverName := t.ServerName
			if serverName == "" {
				serverName = n.Server
			}
			s = client.Security{Kind: "tls", TLS: access.ClientTLS{Enabled: true, ServerName: serverName, Trust: "system", ALPN: t.ALPN}}
			if len(t.Certificate) > 0 {
				if len(t.Certificate) != 1 {
					return c, unsupported()
				}
				s.TLS.Trust = "explicit_ca"
				s.TLS.CACertificate = t.Certificate[0]
			}
		}
	} else if n.SNI != "" || n.ServerName != "" || len(n.ALPN) > 0 || n.SkipVerify {
		return c, unsupported()
	}
	if s.TLS.Validate(s.Kind) != nil {
		return c, invalid()
	}
	options, _ := json.Marshal(module.ClientOptions{Security: security, UDP: udp})
	if name == "" {
		name = "Imported VMess node"
	}
	c.Node = client.RemoteNode{Name: name, Protocol: module.Key(), Endpoint: access.Endpoint{Host: n.Server, Port: port}, Transport: client.Transport{Kind: "tcp"}, Security: s, Options: client.Options{Schema: 1, Data: options}}
	if c.Node.Endpoint.Validate() != nil {
		return Candidate{}, invalid()
	}
	c.Credential = Credential{Kind: access.UUID, Value: n.UUID}
	return c, nil
}
