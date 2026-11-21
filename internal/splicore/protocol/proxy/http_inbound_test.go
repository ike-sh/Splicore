package proxy

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/ports"
)

func TestManagedHTTPCreationRequiresAuthentication(t *testing.T) {
	m := HTTPInbound()
	meta := m.Metadata()
	if meta.Key != Key("http") || !meta.Roles.Inbound || !meta.Roles.Outbound || meta.Availability != ports.Compiled {
		t.Fatal("HTTP profile is not registered as a managed native proxy")
	}
	document := func(host, settings, users string) json.RawMessage {
		return fmt.Appendf(nil, `{"schema":1,"name":"Managed HTTP","listener":{"host":%q,"port":18080},
			"display_endpoint":{"host":"proxy.example","port":18080},"settings":%s,"users":%s}`, host, settings, users)
	}
	const settings = `{"auth":true}`
	const users = `[{"account_name":"first","username":"alice"},{"account_name":"second","username":"bob"}]`
	for _, doc := range []json.RawMessage{
		document("", `{"auth":false}`, users),
		document("", `{"auth":true,"udp":true}`, users),
		document("0.0.0.0", settings, users),
		document("::", settings, users),
		document("192.0.2.20", settings, users),
		document("", settings, `[{"account_name":"first","username":"bad:name"}]`),
		document("", settings, `[{"account_name":"first","username":"alice"},{"account_name":"second","username":"alice"}]`),
		document("", settings, `[{"account_name":"first","username":"alice","expires_at":"2001-01-01T00:00:00Z"}]`),
	} {
		if _, err := m.DecodeCreation(doc); err == nil {
			t.Fatal("HTTP creation accepted unsafe listener or authentication settings")
		}
	}
	for _, tc := range []struct{ host, settings, want string }{
		{"", settings, "127.0.0.1"},
		{"::1", settings, "::1"},
		{"::", `{"auth":true,"allow_cleartext_remote":true}`, "::"},
		{"0.0.0.0", `{"auth":true,"allow_cleartext_remote":true}`, "0.0.0.0"},
	} {
		draft, err := m.DecodeCreation(document(tc.host, tc.settings, users))
		if err != nil || draft.Protocol != Key("http") || draft.Listener.Host != tc.want || draft.Transport != "tcp" || len(draft.Users) != 2 {
			t.Fatal("invalid managed HTTP draft:", err)
		}
		cred, err := m.GenerateCreationCredential(draft.Users[0].Payload)
		if err != nil || cred.Validate() != nil {
			t.Fatal("HTTP creation did not generate an admissible credential:", err)
		}
	}
}
