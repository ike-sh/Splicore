package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestWireGuardBootstrap(t *testing.T) {
	private := base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	public := base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz123456"))
	raw := validConfig(t) + "wireguard_endpoints:\n  - tag: core\n    addresses: ['10.34.0.1/32', 'fd34::1/128']\n    private_key: '" + private + "'\n    listen_port: 0\n    peers:\n      - public_key: '" + public + "'\n        endpoint: 'peer.example:51820'\n        allowed_ips: ['0.0.0.0/0', '::/0']\n"
	config, err := Decode(strings.NewReader(raw))
	if err != nil || len(config.WireGuardEndpoints) != 1 {
		t.Fatal(err)
	}
	for _, invalid := range []string{strings.Replace(raw, "listen_port: 0", "listen_port: -1", 1), strings.Replace(raw, private, "invalid-secret", 1), strings.Replace(raw, "allowed_ips:", "unknown:", 1), raw + "  - tag: core\n"} {
		if _, err = Decode(strings.NewReader(invalid)); err == nil {
			t.Fatal("bad bootstrap accepted")
		}
	}
}
