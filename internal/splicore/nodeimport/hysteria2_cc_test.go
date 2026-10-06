package nodeimport

import (
	"encoding/json"
	"testing"
)

func TestHysteria2ImportRejectsUnsupportedCongestionControl(t *testing.T) {
	for _, format := range []string{"sing-box", "mihomo"} {
		for _, cc := range []string{"", "bbr", "cubic", "unknown"} {
			node := map[string]any{"type": "hysteria2", "server": "example.test", "password": "synthetic-password"}
			var body any
			if format == "sing-box" {
				node["tag"] = "synthetic HY2"
				node["server_port"] = 443
				if cc != "" {
					node["congestion_control"] = cc
				}
				body = node
			} else {
				node["name"] = "synthetic HY2"
				node["port"] = 443
				if cc != "" {
					node["congestion-controller"] = cc
				}
				body = map[string]any{"proxies": []any{node}}
			}
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			result, err := parseExternal(format, encoded)
			if err != nil {
				t.Fatal(err)
			}
			if cc == "" {
				if len(result.Candidates) != 1 || len(result.Issues) != 0 {
					t.Fatalf("%s default: %+v", format, result)
				}
			} else if len(result.Candidates) != 0 || len(result.Issues) != 1 || result.Issues[0].Code != "unsupported_client_capability" {
				t.Fatalf("%s %s accepted ignored CC: %+v", format, cc, result)
			}
		}
	}
}
