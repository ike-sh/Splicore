package vless

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
)

func TestVisionDeferredAtProtocolBoundaries(t *testing.T) {
	for _, security := range []Security{Plain, TLS, Reality} {
		t.Run(string(security), func(t *testing.T) {
			s := realitySettings(t)
			s.Security, s.Flow = security, Vision
			data, _ := json.Marshal(s)
			id := func() identity.ID {
				value, err := identity.NewID()
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
			i := access.Inbound{ID: id(), NodeID: id(), Name: "synthetic", Protocol: Key(security), Engine: "native", Enabled: true,
				Listeners:        []access.Listener{{ID: id(), Transport: "tcp", Endpoint: access.Endpoint{Host: "127.0.0.1", Port: 12345}}},
				DisplayEndpoints: []access.DisplayEndpoint{{ID: id(), Endpoint: access.Endpoint{Host: "edge.synthetic.test", Port: 443}}},
				Settings:         access.Settings{Schema: 1, Data: data}, Stamp: identity.NewStamp(time.Now())}
			module := Module{Security: security}
			doc, _ := json.Marshal(map[string]any{"schema": 1, "name": "synthetic", "listener": i.Listeners[0].Endpoint,
				"display_endpoint": i.DisplayEndpoints[0].Endpoint, "settings": json.RawMessage(data), "users": []any{map[string]any{"account_name": "Alice"}}})
			options, _ := json.Marshal(ClientOptions{Security: security, Flow: Vision, PacketEncoding: "xudp"})
			checks := map[string]func() error{
				"config":          func() error { _, err := Decode(data); return err },
				"creation-import": func() error { _, err := module.DecodeCreation(doc); return err },
				"materializer":    func() error { _, err := module.MaterializeCreation(ports.CreationDraft{Settings: data}); return err },
				"inbound":         func() error { return module.ValidateInbound(i) },
				"runtime": func() error {
					_, err := module.BuildRuntime(context.Background(), ports.RuntimeIntent{Inbound: i})
					return err
				},
				"client-profile": func() error {
					_, err := module.BuildClientProfile(context.Background(), ports.AuthorizedBinding{Inbound: i})
					return err
				},
				"client-options": func() error { _, err := DecodeClientOptions(options); return err },
			}
			for name, check := range checks {
				t.Run(name, func(t *testing.T) {
					var typed *identity.Error
					if err := check(); !errors.As(err, &typed) || typed.Code != identity.NotImplemented {
						t.Fatalf("unsupported flow was not rejected with a typed error: %v", err)
					}
				})
			}
			capability := module.Capabilities(ports.CapabilityContext{Engine: "native"})
			if capability.Security.Vision || len(capability.Security.Flows) != 1 || capability.Security.Flows[0] != string(NoFlow) {
				t.Fatal("unsupported Vision advertised")
			}
		})
	}
}
