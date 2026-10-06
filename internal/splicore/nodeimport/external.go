package nodeimport

import (
	"bytes"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/provider"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	hm "github.com/ike-sh/Splicore/internal/splicore/protocol/hysteria2"
	mm "github.com/ike-sh/Splicore/internal/splicore/protocol/mieru"
	ssm "github.com/ike-sh/Splicore/internal/splicore/protocol/shadowsocks"
	sm "github.com/ike-sh/Splicore/internal/splicore/protocol/snell"
	tm "github.com/ike-sh/Splicore/internal/splicore/protocol/tuic"
	vm "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	"gopkg.in/yaml.v3"
	"io"
	"strings"
)

// YAMLJSON accepts only bounded plain data: no aliases, merges, custom tags,
// duplicate mapping keys or trailing documents. JSON input uses the same gate.
func YAMLJSON(body []byte) ([]byte, error) {
	if len(body) > provider.MaxBody {
		return nil, invalid()
	}
	d := yaml.NewDecoder(bytes.NewReader(body))
	var root yaml.Node
	if d.Decode(&root) != nil || len(root.Content) != 1 || d.Decode(new(yaml.Node)) != io.EOF {
		return nil, invalid()
	}
	count := 0
	var walk func(*yaml.Node, int) (any, error)
	walk = func(n *yaml.Node, depth int) (any, error) {
		count++
		if count > 60000 || depth > 16 || n.Alias != nil || n.Anchor != "" {
			return nil, invalid()
		}
		switch n.Kind {
		case yaml.MappingNode:
			m := map[string]any{}
			for i := 0; i < len(n.Content); i += 2 {
				k := n.Content[i]
				if k.Kind != yaml.ScalarNode || k.Tag != "!!str" {
					return nil, invalid()
				}
				if _, ok := m[k.Value]; ok {
					return nil, invalid()
				}
				v, e := walk(n.Content[i+1], depth+1)
				if e != nil {
					return nil, e
				}
				m[k.Value] = v
			}
			return m, nil
		case yaml.SequenceNode:
			a := []any{}
			for _, v := range n.Content {
				x, e := walk(v, depth+1)
				if e != nil {
					return nil, e
				}
				a = append(a, x)
			}
			return a, nil
		case yaml.ScalarNode:
			switch n.Tag {
			case "!!str", "!!int", "!!bool", "!!null", "!!float":
			default:
				return nil, invalid()
			}
			var v any
			if n.Decode(&v) != nil {
				return nil, invalid()
			}
			return v, nil
		default:
			return nil, invalid()
		}
	}
	v, e := walk(root.Content[0], 0)
	if e != nil {
		return nil, e
	}
	return json.Marshal(v)
}

type externalTLS struct {
	Enabled     bool     `json:"enabled"`
	ServerName  string   `json:"server_name"`
	Insecure    bool     `json:"insecure"`
	ALPN        []string `json:"alpn"`
	Certificate []string `json:"certificate"`
	Reality     *struct {
		Enabled   bool   `json:"enabled"`
		PublicKey string `json:"public_key"`
		ShortID   string `json:"short_id"`
	} `json:"reality,omitempty"`
	UTLS *struct {
		Enabled     bool   `json:"enabled"`
		Fingerprint string `json:"fingerprint"`
	} `json:"utls,omitempty"`
}
type externalNode struct {
	Type           string       `json:"type"`
	Name           string       `json:"name"`
	Tag            string       `json:"tag"`
	Server         string       `json:"server"`
	Port           uint16       `json:"port"`
	ServerPort     uint16       `json:"server_port"`
	Version        int          `json:"version"`
	PSK            string       `json:"psk"`
	Password       string       `json:"password"`
	Method         string       `json:"method"`
	Cipher         string       `json:"cipher"`
	Network        string       `json:"network"`
	UUID           string       `json:"uuid"`
	Username       string       `json:"username"`
	TLS            *externalTLS `json:"tls"`
	SNI            string       `json:"sni"`
	SkipVerify     bool         `json:"skip-cert-verify"`
	ALPN           []string     `json:"alpn"`
	Transport      string       `json:"transport"`
	MTU            int          `json:"mtu"`
	Multiplexing   string       `json:"multiplexing"`
	UDP            *bool        `json:"udp"`
	Congestion     string       `json:"congestion_control"`
	CongestionM    string       `json:"congestion-controller"`
	Relay          string       `json:"udp_relay_mode"`
	RelayM         string       `json:"udp-relay-mode"`
	ZeroRTT        bool         `json:"zero_rtt_handshake"`
	ReduceRTT      bool         `json:"reduce-rtt"`
	Heartbeat      string       `json:"heartbeat"`
	HeartbeatM     int          `json:"heartbeat-interval"`
	Flow           string       `json:"flow"`
	PacketEncoding string       `json:"packet_encoding"`
	RealityM       *struct {
		PublicKey string `json:"public-key"`
		ShortID   string `json:"short-id"`
	} `json:"reality-opts"`
	Fingerprint string `json:"client-fingerprint"`
}

func parseExternal(format string, body []byte) (Result, error) {
	var out Result
	var e error
	if format == "mihomo" {
		body, e = YAMLJSON(body)
		if e != nil {
			return out, e
		}
	}
	var root map[string]json.RawMessage
	if jsonstrict.DecodeLimit(body, &root, provider.MaxBody) != nil {
		return out, invalid()
	}
	var entries []json.RawMessage
	field := "proxies"
	if format == "sing-box" {
		field = "outbounds"
	}
	if _, ok := root[field]; ok {
		if len(root) != 1 || json.Unmarshal(root[field], &entries) != nil {
			return out, invalid()
		}
	} else if format == "sing-box" {
		entries = []json.RawMessage{body}
	} else {
		return out, invalid()
	}
	if len(entries) > provider.MaxNodes {
		return out, invalid()
	}
	for i, b := range entries {
		var n externalNode
		if jsonstrict.DecodeLimit(b, &n, provider.MaxLine) != nil {
			out.Issues = append(out.Issues, Issue{i + 1, "Unsupported", "unknown_client_field"})
			continue
		}
		c, e := externalCandidate(format, n)
		if e != nil {
			out.Issues = append(out.Issues, Issue{i + 1, "Unsupported", "unsupported_client_capability"})
			continue
		}
		out.Candidates = append(out.Candidates, c)
	}
	return out, nil
}
func externalCandidate(format string, n externalNode) (Candidate, error) {
	var c Candidate
	if n.UDP != nil && !*n.UDP && n.Type != "ss" && n.Type != "shadowsocks" {
		return c, unsupported()
	}
	if n.Type != "snell" && n.Type != "tuic" && n.Version != 0 {
		return c, unsupported()
	}
	port := n.Port
	name := n.Name
	if format == "sing-box" {
		if n.Port != 0 || n.Name != "" || n.SNI != "" || n.SkipVerify || len(n.ALPN) > 0 || n.RealityM != nil || n.Fingerprint != "" || n.CongestionM != "" || n.RelayM != "" || n.ReduceRTT || n.HeartbeatM != 0 {
			return c, unsupported()
		}
		port = n.ServerPort
		name = n.Tag
	} else if n.ServerPort != 0 || n.Tag != "" || n.TLS != nil || n.PacketEncoding != "" || n.Congestion != "" || n.Relay != "" || n.Heartbeat != "" || n.ZeroRTT {
		return c, unsupported()
	}
	c.Node = client.RemoteNode{Name: name, Endpoint: access.Endpoint{Host: n.Server, Port: port}, Transport: client.Transport{Kind: "tcp"}, Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: json.RawMessage(`{}`)}}
	if n.SkipVerify || n.ZeroRTT || n.ReduceRTT {
		return c, unsupported()
	}
	// Public trust only; unsupported TLS extensions cannot reach runtime options.
	tls := access.ClientTLS{Enabled: true, Trust: "system", ServerName: n.SNI, ALPN: n.ALPN}
	if n.TLS != nil {
		if !n.TLS.Enabled || n.TLS.Insecure {
			return c, unsupported()
		}
		tls.ServerName = n.TLS.ServerName
		tls.ALPN = n.TLS.ALPN
		if len(n.TLS.Certificate) > 0 {
			tls.CACertificate = strings.Join(n.TLS.Certificate, "\n")
			tls.Trust = "explicit_ca"
		}
	}
	if tls.ServerName == "" {
		tls.ServerName = n.Server
	}
	options := any(map[string]any{})
	switch n.Type {
	case "ss", "shadowsocks":
		if format == "mihomo" && (n.Type != "ss" || n.Method != "") || format == "sing-box" && (n.Type != "shadowsocks" || n.Cipher != "") || n.PSK != "" || n.UUID != "" || n.Username != "" || n.TLS != nil || n.SNI != "" || len(n.ALPN) > 0 || n.Network != "" && n.Network != "tcp" {
			return c, unsupported()
		}
		method := n.Method + n.Cipher
		m, e := ssm.Lookup(method)
		if e != nil {
			return c, e
		}
		c.Node.Protocol = ssm.Key(m.Edition)
		udp := n.Network != "tcp"
		if n.UDP != nil {
			if format != "mihomo" || n.Network != "" {
				return c, unsupported()
			}
			udp = *n.UDP
		}
		options = ssm.ClientOptions{Method: method, UDP: udp}
		kind := access.Password
		if m.Edition == "2022" {
			kind = access.PSK
		}
		c.Credential = Credential{kind, n.Password}
	case "snell":
		if n.Password != "" || n.UUID != "" || n.Username != "" || n.Version < 4 || n.Version > 6 || n.TLS != nil || n.SNI != "" || len(n.ALPN) > 0 {
			return c, unsupported()
		}
		c.Node.Protocol = sm.Key(n.Version)
		options = map[string]int{"version": n.Version}
		c.Credential = Credential{access.PSK, n.PSK}
	case "hysteria2":
		if n.PSK != "" || n.UUID != "" || n.Username != "" || n.Version != 0 {
			return c, unsupported()
		}
		c.Node.Protocol = hm.Key()
		c.Node.Transport.Kind = "quic"
		if len(tls.ALPN) == 0 {
			tls.ALPN = []string{"h3"}
		}
		c.Node.Security = client.Security{Kind: "tls", TLS: tls}
		c.Credential = Credential{access.Password, n.Password}
	case "tuic":
		if n.PSK != "" || n.Username != "" || n.Version != 0 && n.Version != 5 {
			return c, unsupported()
		}
		cong := n.Congestion + n.CongestionM
		if cong == "" {
			cong = "cubic"
		}
		relay := n.Relay + n.RelayM
		if relay == "" {
			relay = "native"
		}
		if cong != "cubic" || relay != "native" || n.Heartbeat != "" && n.Heartbeat != "10s" || n.HeartbeatM != 0 && n.HeartbeatM != 10000 {
			return c, unsupported()
		}
		c.Node.Protocol = tm.Key()
		c.Node.Transport.Kind = "quic"
		if len(tls.ALPN) == 0 {
			tls.ALPN = []string{"h3"}
		}
		c.Node.Security = client.Security{Kind: "tls", TLS: tls}
		b, _ := json.Marshal(map[string]string{"uuid": n.UUID, "password": n.Password})
		c.Credential = Credential{access.UUIDPassword, string(b)}
		options = tm.ClientOptions{Version: 5, CongestionControl: "cubic", UDPRelayMode: "native"}
	case "vless":
		if n.PSK != "" || n.Password != "" || n.Username != "" || n.Flow != "" && n.Flow != "none" || n.PacketEncoding != "" && n.PacketEncoding != "xudp" {
			return c, unsupported()
		}
		security := vm.Plain
		if n.TLS != nil || format == "mihomo" && n.SNI != "" {
			security = vm.TLS
			c.Node.Security = client.Security{Kind: "tls", TLS: tls}
		}
		if n.RealityM != nil || n.TLS != nil && n.TLS.Reality != nil {
			security = vm.Reality
			tls.Trust = "reality"
			if n.RealityM != nil {
				tls.RealityPublicKey = n.RealityM.PublicKey
				tls.RealityShortID = n.RealityM.ShortID
				if n.Fingerprint != "chrome" {
					return c, unsupported()
				}
			} else {
				r := n.TLS.Reality
				if !r.Enabled || n.TLS.UTLS == nil || !n.TLS.UTLS.Enabled || n.TLS.UTLS.Fingerprint != "chrome" {
					return c, unsupported()
				}
				tls.RealityPublicKey = r.PublicKey
				tls.RealityShortID = r.ShortID
			}
			c.Node.Security = client.Security{Kind: "reality", TLS: tls}
		} else if n.TLS != nil && n.TLS.UTLS != nil || n.Fingerprint != "" {
			return c, unsupported()
		}
		c.Node.Protocol = vm.Key(security)
		options = vm.ClientOptions{Security: security, Flow: vm.NoFlow, PacketEncoding: "xudp"}
		c.Credential = Credential{access.UUID, n.UUID}
	case "mieru":
		if format != "mihomo" || n.PSK != "" || n.UUID != "" || n.Version != 0 || n.TLS != nil || n.SNI != "" || len(n.ALPN) > 0 || n.UDP != nil && !*n.UDP {
			return c, unsupported()
		}
		transport := strings.ToLower(n.Transport)
		mux := strings.ToLower(strings.TrimPrefix(n.Multiplexing, "MULTIPLEXING_"))
		if mux == "" {
			mux = "default"
		}
		mtu := n.MTU
		if mtu == 0 {
			mtu = 1500
		}
		c.Node.Protocol = mm.Key()
		c.Node.Transport.Kind = transport
		options = mm.Settings{Transport: transport, MTU: mtu, Multiplex: mux}
		b, _ := json.Marshal(map[string]string{"username": n.Username, "password": n.Password})
		c.Credential = Credential{access.UsernamePassword, string(b)}
	default:
		return c, unsupported()
	}
	// Protocol-specific options on another protocol must never be discarded.
	if n.Type != "ss" && n.Type != "shadowsocks" && (n.Method != "" || n.Cipher != "" || n.Network != "") {
		return c, unsupported()
	}
	if n.Type != "tuic" && (n.Congestion != "" || n.CongestionM != "" || n.Relay != "" || n.RelayM != "" || n.Heartbeat != "" || n.HeartbeatM != 0) || n.Type != "mieru" && (n.Transport != "" || n.MTU != 0 || n.Multiplexing != "") || n.Type != "vless" && (n.Flow != "" || n.PacketEncoding != "" || n.RealityM != nil || n.Fingerprint != "" || n.TLS != nil && (n.TLS.Reality != nil || n.TLS.UTLS != nil)) {
		return c, unsupported()
	}
	c.Node.Options.Data, _ = json.Marshal(options)
	return c, nil
}
func parseMieru(body []byte) (Result, error) {
	var out Result
	var config struct {
		Profiles []struct {
			Name string `json:"profileName"`
			User struct {
				Name     string `json:"name"`
				Password string `json:"password"`
			} `json:"user"`
			Servers []struct {
				IP       string `json:"ipAddress"`
				Domain   string `json:"domainName"`
				Bindings []struct {
					Port     uint16 `json:"port"`
					Protocol string `json:"protocol"`
				} `json:"portBindings"`
			} `json:"servers"`
			MTU       int `json:"mtu"`
			Multiplex *struct {
				Level string `json:"level"`
			} `json:"multiplexing"`
		} `json:"profiles"`
		Active string `json:"activeProfile"`
	}
	if jsonstrict.DecodeLimit(body, &config, provider.MaxBody) != nil || len(config.Profiles) > provider.MaxNodes {
		return out, invalid()
	}
	active := config.Active == ""
	for i, p := range config.Profiles {
		if p.Name == config.Active {
			active = true
		}
		if len(p.Servers) != 1 || len(p.Servers[0].Bindings) != 1 {
			out.Issues = append(out.Issues, Issue{i + 1, "Unsupported", "mieru_multiple_endpoints"})
			continue
		}
		s := p.Servers[0]
		if s.IP != "" && s.Domain != "" {
			return out, invalid()
		}
		host := s.IP
		if host == "" {
			host = s.Domain
		}
		transport := strings.ToLower(s.Bindings[0].Protocol)
		mux := "default"
		if p.Multiplex != nil {
			mux = strings.ToLower(strings.TrimPrefix(p.Multiplex.Level, "MULTIPLEXING_"))
		}
		mtu := p.MTU
		if mtu == 0 {
			mtu = 1500
		}
		options, _ := json.Marshal(mm.Settings{Transport: transport, MTU: mtu, Multiplex: mux})
		credential, _ := json.Marshal(map[string]string{"username": p.User.Name, "password": p.User.Password})
		out.Candidates = append(out.Candidates, Candidate{Node: client.RemoteNode{Name: p.Name, Protocol: mm.Key(), Endpoint: access.Endpoint{Host: host, Port: s.Bindings[0].Port}, Transport: client.Transport{Kind: transport}, Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: options}}, Credential: Credential{access.UsernamePassword, string(credential)}})
	}
	if !active {
		return out, invalid()
	}
	return out, nil
}
