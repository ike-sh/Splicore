package nodeimport

import (
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	hm "github.com/ike-sh/Splicore/internal/splicore/protocol/hysteria2"
)

func parseHysteriaURI(raw string) (Candidate, error) {
	v, e := hm.ParseURI(raw)
	if e != nil {
		return Candidate{}, e
	}
	return Candidate{Node: client.RemoteNode{Name: v.Name, Protocol: hm.Key(), Endpoint: v.Endpoint, Transport: v.Transport, Security: client.Security{Kind: "tls", TLS: v.TLS}, Options: client.Options{Schema: 1, Data: json.RawMessage(`{}`)}}, Credential: Credential{Kind: access.Password, Value: v.Password.Reveal()}}, nil
}
