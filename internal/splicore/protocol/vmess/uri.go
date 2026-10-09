package vmess

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	streamcfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type URI struct {
	Transport streamcfg.Config
	Endpoint  access.Endpoint
	UUID      secret.Value
	Security  string
	TLS       access.ClientTLS
	Name      string
}

func (URI) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("VMessURI{[REDACTED]}")) }
func scalar(b json.RawMessage, required bool) (string, error) {
	if len(b) == 0 {
		if required {
			return "", invalid()
		}
		return "", nil
	}
	var v string
	if b[0] == '"' {
		if json.Unmarshal(b, &v) != nil {
			return "", invalid()
		}
		return v, nil
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return "", invalid()
		}
	}
	return string(b), nil
}
func ParseURI(raw string) (URI, error) {
	var v URI
	if len(raw) > 4096 || !strings.HasPrefix(raw, "vmess://") || !utf8.ValidString(raw) || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return v, invalid()
	}
	encoded := strings.TrimPrefix(raw, "vmess://")
	var b []byte
	var err error
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		b, err = encoding.Strict().DecodeString(encoded)
		if err == nil {
			break
		}
	}
	if err != nil || len(b) > 3072 || !utf8.Valid(b) {
		return v, invalid()
	}
	defer clear(b)
	if _, err := Object(b, []string{"v", "ps", "add", "port", "id", "aid", "scy", "net", "type", "host", "path", "tls", "sni", "alpn", "fp"}, false); err != nil {
		return v, err
	}
	var w struct {
		V    json.RawMessage `json:"v"`
		PS   string          `json:"ps"`
		Add  string          `json:"add"`
		Port json.RawMessage `json:"port"`
		ID   string          `json:"id"`
		AID  json.RawMessage `json:"aid"`
		SCY  string          `json:"scy"`
		Net  string          `json:"net"`
		Type string          `json:"type"`
		Host string          `json:"host"`
		Path string          `json:"path"`
		TLS  string          `json:"tls"`
		SNI  string          `json:"sni"`
		ALPN string          `json:"alpn"`
		FP   string          `json:"fp"`
	}
	if jsonstrict.Decode(b, &w) != nil || !noNull(b) {
		return v, invalid()
	}
	var exact map[string]json.RawMessage
	_ = json.Unmarshal(b, &exact)
	allowed := map[string]bool{}
	for _, name := range []string{"v", "ps", "add", "port", "id", "aid", "scy", "net", "type", "host", "path", "tls", "sni", "alpn", "fp"} {
		allowed[name] = true
	}
	for name := range exact {
		if !allowed[name] {
			return v, invalid()
		}
	}
	version, e := scalar(w.V, false)
	if e != nil || version != "" && version != "2" {
		return v, invalid()
	}
	aid, e := scalar(w.AID, false)
	if e != nil {
		return v, e
	}
	if aid != "" && aid != "0" {
		return v, Unsupported("unsupported_legacy_vmess")
	}
	transport := streamcfg.Config{Kind: w.Net, Path: w.Path, Host: w.Host}
	if transport.Kind == "" {
		transport.Kind = "tcp"
	}
	if transport.Kind == "grpc" {
		transport.ServiceName = w.Path
		transport.Path = ""
	}
	if transport.Validate() != nil || w.Type != "" && w.Type != "none" && !(transport.Kind == "grpc" && w.Type == "gun") || w.FP != "" {
		return v, Unsupported("unsupported_transport")
	}
	port, e := scalar(w.Port, true)
	if e != nil {
		return v, e
	}
	n, e := strconv.ParseUint(port, 10, 16)
	if e != nil || n == 0 {
		return v, invalid()
	}
	v = URI{Endpoint: access.Endpoint{Host: w.Add, Port: uint16(n)}, UUID: secret.New(w.ID), Security: w.SCY, Name: w.PS, Transport: transport}
	if v.Security == "" {
		v.Security = "auto"
	}
	if _, err = Security(v.Security); err != nil {
		return URI{}, err
	}
	if v.Name == "" {
		v.Name = "Imported VMess node"
	}
	if (access.UUIDPayload{UUID: v.UUID}).Validate() != nil {
		return URI{}, InvalidCredential()
	}
	if v.Endpoint.Validate() != nil || !identity.Label(v.Name, 128) {
		return URI{}, invalid()
	}
	for _, s := range []string{w.Add, w.PS, w.ID, w.SNI, w.ALPN} {
		if strings.IndexFunc(s, unicode.IsControl) >= 0 {
			return URI{}, invalid()
		}
	}
	switch w.TLS {
	case "", "none":
		if w.SNI != "" || w.ALPN != "" {
			return URI{}, invalid()
		}
	case "tls":
		sni := w.SNI
		if sni == "" {
			sni = w.Add
		}
		v.TLS = access.ClientTLS{Enabled: true, ServerName: sni, Trust: "system"}
		if w.ALPN != "" {
			v.TLS.ALPN = strings.Split(w.ALPN, ",")
		}
		if v.TLS.Validate("tls") != nil {
			return URI{}, invalid()
		}
	default:
		return URI{}, Unsupported("unsupported_transport")
	}
	kind := "none"
	if v.TLS.Enabled {
		kind = "tls"
	}
	if v.Transport.ValidatePair("vmess", kind) != nil {
		return URI{}, Unsupported("unsupported_transport")
	}
	return v, nil
}
func EncodeURI(v URI) (string, error) {
	if v.Endpoint.Validate() != nil || (access.UUIDPayload{UUID: v.UUID}).Validate() != nil || !identity.Label(v.Name, 128) {
		return "", invalid()
	}
	if _, err := Security(v.Security); err != nil {
		return "", err
	}
	w := map[string]any{"v": "2", "ps": v.Name, "add": v.Endpoint.Host, "port": strconv.Itoa(int(v.Endpoint.Port)), "id": v.UUID.Reveal(), "aid": "0", "scy": v.Security, "net": "tcp", "type": "none", "host": "", "path": "", "tls": ""}
	if v.Transport.Validate() != nil || len(v.Transport.Headers) > 0 {
		return "", Unsupported("unsupported_transport")
	}
	w["net"] = v.Transport.Type()
	w["host"] = v.Transport.Host
	if v.Transport.Type() == "ws" || v.Transport.Type() == "httpupgrade" {
		w["path"] = v.Transport.HTTPPath()
	}
	if v.Transport.Type() == "grpc" {
		if v.Transport.Host != "" {
			return "", Unsupported("unsupported_transport")
		}
		w["path"] = v.Transport.Service()
		w["type"] = "gun"
	}
	if v.TLS.Enabled {
		if v.TLS.Validate("tls") != nil || v.TLS.Trust != "system" || v.TLS.CACertificate != "" {
			return "", Unsupported("VMess URI cannot represent trust")
		}
		for _, a := range v.TLS.ALPN {
			if strings.Contains(a, ",") {
				return "", Unsupported("VMess URI cannot represent ALPN")
			}
		}
		w["tls"], w["sni"], w["alpn"] = "tls", v.TLS.ServerName, strings.Join(v.TLS.ALPN, ",")
	} else if v.TLS.Validate("none") != nil {
		return "", invalid()
	}
	b, err := json.Marshal(w)
	if err != nil {
		return "", err
	}
	defer clear(b)
	out := "vmess://" + base64.StdEncoding.EncodeToString(b)
	if len(out) > 4096 {
		return "", invalid()
	}
	return out, nil
}
