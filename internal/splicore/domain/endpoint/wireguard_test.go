package endpoint_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/wireguardendpoint"
)

func valid(t *testing.T) E.WireGuard {
	t.Helper()
	private, _, err := wireguardendpoint.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, public, err := wireguardendpoint.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := E.ParseSecret(private)
	if err != nil {
		t.Fatal(err)
	}
	return E.WireGuard{Tag: "wg0", PrivateKey: secret, Addresses: []string{"10.34.0.1/32", "fd34::1/128"}, Peers: []E.WireGuardPeer{{PublicKey: public, Endpoint: "peer.example:51820", AllowedIPs: []string{"0.0.0.0/0", "::/0"}}}}
}

func TestWireGuardInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		change func(*E.WireGuard)
	}{
		{"missing-private", func(c *E.WireGuard) { c.PrivateKey = E.Secret{} }},
		{"zero-private", func(c *E.WireGuard) {
			c.PrivateKey, _ = E.ParseSecret(base64.StdEncoding.EncodeToString(make([]byte, 32)))
		}},
		{"missing-address", func(c *E.WireGuard) { c.Addresses = nil }},
		{"bad-local-prefix", func(c *E.WireGuard) { c.Addresses = []string{"10.1.1.1/33"} }},
		{"duplicate-key", func(c *E.WireGuard) { c.Peers = append(c.Peers, c.Peers[0]) }},
		{"bad-public-base64", func(c *E.WireGuard) { c.Peers[0].PublicKey = "!" }},
		{"short-public", func(c *E.WireGuard) { c.Peers[0].PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 31)) }},
		{"zero-public", func(c *E.WireGuard) { c.Peers[0].PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32)) }},
		{"bad-endpoint", func(c *E.WireGuard) { c.Peers[0].Endpoint = "not:an:endpoint" }},
		{"bad-port", func(c *E.WireGuard) { c.Peers[0].Endpoint = "example.com:0" }},
		{"bad-domain", func(c *E.WireGuard) { c.Peers[0].Endpoint = "-invalid.example:10" }},
		{"bad-allowed-ip", func(c *E.WireGuard) { c.Peers[0].AllowedIPs = []string{"fd00::1/129"} }},
		{"missing-peers", func(c *E.WireGuard) { c.Peers = nil }},
		{"low-mtu", func(c *E.WireGuard) { c.MTU = 1279 }},
		{"high-mtu", func(c *E.WireGuard) { c.MTU = 9001 }},
		{"negative-keepalive", func(c *E.WireGuard) { c.Peers[0].PersistentKeepaliveInterval = -1 }},
		{"large-keepalive", func(c *E.WireGuard) { c.Peers[0].PersistentKeepaliveInterval = 65536 }},
		{"nonzero-reserved", func(c *E.WireGuard) { c.Reserved = []int{0, 0, 1} }},
		{"wrong-reserved-size", func(c *E.WireGuard) { c.Reserved = []int{0} }},
		{"invalid-listen-port", func(c *E.WireGuard) { c.ListenPort = 65536 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := valid(t)
			test.change(&c)
			if c.Validate() == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	for _, value := range []string{"", "!", base64.StdEncoding.EncodeToString(make([]byte, 31)), base64.StdEncoding.EncodeToString(make([]byte, 33)), base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"} {
		var peer E.WireGuardPeer
		b, _ := json.Marshal(map[string]string{"pre_shared_key": value})
		var endpoint E.WireGuard
		privateJSON, _ := json.Marshal(map[string]string{"private_key": value})
		if json.Unmarshal(privateJSON, &endpoint) == nil {
			t.Fatal("invalid private key encoding/length accepted")
		}
		if json.Unmarshal(b, &peer) == nil {
			t.Fatal("invalid PSK encoding/length accepted")
		}
	}
}

func TestWireGuardKeysSecretsAndClone(t *testing.T) {
	c := valid(t)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.InnerMTU() != 1420 {
		t.Fatal("wrong default MTU")
	}
	private := c.PrivateKey.Reveal()
	secret := E.EncodeKey(private)
	c.Peers[0].PreSharedKey = c.PrivateKey
	for _, encoded := range []string{fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), string(mustJSON(t, c))} {
		if strings.Contains(encoded, secret) {
			t.Fatal("private material leaked")
		}
	}
	clone := c.Clone()
	clone.Peers[0].AllowedIPs[0] = "192.0.2.0/24"
	clone.Addresses[0] = "10.1.1.1/32"
	if c.Peers[0].AllowedIPs[0] != "0.0.0.0/0" || c.Addresses[0] != "10.34.0.1/32" || clone.PrivateKey.Reveal() != private {
		t.Fatal("configuration snapshot is not independent")
	}
	c.Reserved = []int{0, 0, 0}
	c.Peers[0].Endpoint = "[::1]:51820"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
