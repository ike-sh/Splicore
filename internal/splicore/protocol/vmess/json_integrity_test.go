package vmess_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/nodeimport"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/vmess"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
)

func TestReviewFix1ManagedAliasMatrix(t *testing.T) {
	for _, tc := range []struct {
		field, alias, a, b string
		client             bool
	}{
		{"alter_id", "ALTER_ID", "0", "64", false},
		{"transport", "Transport", `"tcp"`, `"ws"`, false},
		{"security", "Security", `"none"`, `"reality"`, false},
		{"payload_security", "PAYLOAD_SECURITY", `"none"`, `"aes-128-cfb"`, false},
		{"alter_id", "ALTER_ID", "0", "64", true},
		{"security", "Security", `"none"`, `"aes-128-cfb"`, true},
		{"udp", "UDP", "true", "false", true},
	} {
		decode := func(b string) error {
			if tc.client {
				_, e := module.DecodeClientOptions([]byte(b))
				return e
			}
			_, e := module.Decode([]byte(b))
			return e
		}
		for _, reverse := range []bool{false, true} {
			a, b := fmt.Sprintf(`%q:%s`, tc.field, tc.a), fmt.Sprintf(`%q:%s`, tc.alias, tc.b)
			if reverse {
				a, b = b, a
			}
			err := decode("{" + a + "," + b + "}")
			kind, code, ok := module.ImportError(err)
			if !ok || kind != "Invalid" || code != "conflicting_field" {
				t.Fatalf("%s client%v reverse%v: %v", tc.field, tc.client, reverse, err)
			}
			t.Logf("conflict field=%s client=%v reverse=%v code=%s", tc.field, tc.client, reverse, code)
		}
		if err := decode(fmt.Sprintf(`{%q:%s,%q:%s}`, tc.field, tc.a, tc.alias, tc.a)); err != nil {
			t.Fatal("equal aliases", tc.field, err)
		}
		if err := decode(fmt.Sprintf(`{%q:%s}`, tc.alias, tc.a)); err != nil {
			t.Fatal("single historical alias", tc.field, err)
		}
	}
	for _, b := range []string{`{"alter_id":64,"ALTER_ID":64}`, `{"ALTER_ID":64,"alter_id":64}`} {
		_, err := module.Decode([]byte(b))
		_, code, ok := module.ImportError(err)
		if !ok || code != "unsupported_legacy_vmess" {
			t.Fatal("equal positive legacy aliases", err)
		}
	}
	for _, b := range []string{`{}`, `{"alter_id":0}`, `{"udp":false}`} {
		if _, err := module.DecodeClientOptions([]byte(b)); err != nil {
			t.Fatal("presence/zero", err)
		}
	}
	missing, _ := module.DecodeClientOptions([]byte(`{}`))
	zero, _ := module.DecodeClientOptions([]byte(`{"udp":false}`))
	if !missing.UDP || zero.UDP {
		t.Fatal("absent/false collapsed")
	}
}

func TestReviewFix1DuplicatesAndBounds(t *testing.T) {
	for _, b := range []string{`{"alter_id":0,"alter_id":0}`, `{"alter_id":64,"alter_id":0}`, `{"alter_id":0,"alter_id":64}`} {
		_, err := module.Decode([]byte(b))
		_, code, ok := module.ImportError(err)
		if !ok || code != "conflicting_field" {
			t.Fatal("exact duplicate", err)
		}
	}
	for _, b := range []string{`{"transport":null}`, `{"alter_id":null}`, `{"udp":null}`, `{"security":[]}`, `{} {}`, "{" + strings.Repeat(`"udp":true,`, 10000) + `"udp":true}`} {
		if _, err := module.DecodeClientOptions([]byte(b)); err == nil {
			t.Fatal("malformed/bounded input accepted")
		}
	}
	// Large unequal integers must never compare equal after float conversion.
	_, err := module.Decode([]byte(`{"alter_id":9007199254740992,"ALTER_ID":9007199254740993}`))
	_, code, ok := module.ImportError(err)
	if !ok || code != "conflicting_field" {
		t.Fatal("integer precision", err)
	}
	// Exercise the independent member bound with many equal, distinct case
	// spellings; aliases are counted even when they normalize to one field.
	var members []string
	for i := range 65 {
		key := []byte("payload_security")
		for bit := range 7 {
			if i&(1<<bit) != 0 {
				key[bit] -= 'a' - 'A'
			}
		}
		members = append(members, fmt.Sprintf(`%q:"none"`, key))
	}
	if _, err := module.Decode([]byte("{" + strings.Join(members[:64], ",") + "}")); err != nil {
		t.Fatal("64 members", err)
	}
	if _, err := module.Decode([]byte("{" + strings.Join(members, ",") + "}")); err == nil {
		t.Fatal("65 members accepted")
	}
	uriBase := `"add":"localhost","port":443,"id":"` + syntheticUUID + `"`
	for _, tail := range []string{`"aid":1,"aid":0`, `"aid":0,"aid":1`, `"aid":0,"aid":0`} {
		_, err := module.ParseURI(link("{" + uriBase + "," + tail + "}"))
		_, code, ok := module.ImportError(err)
		if !ok || code != "conflicting_field" {
			t.Fatal("URI duplicate", err)
		}
	}
}

func TestReviewFix1NestedAndCredentialAliases(t *testing.T) {
	for _, pair := range []string{
		`"server_name":"first.test","Server_Name":"second.test"`,
		`"certificate_file":"/a","Certificate_File":"/b"`,
		`"private_key_file":"/a","PRIVATE_KEY_FILE":"/b"`,
		`"ca_certificate":"first","CA_CERTIFICATE":"second"`,
	} {
		parts := strings.Split(pair, ",")
		for _, reverse := range []bool{false, true} {
			p := parts[0] + "," + parts[1]
			if reverse {
				p = parts[1] + "," + parts[0]
			}
			_, err := module.Decode([]byte(`{"security":"tls","tls":{` + p + `}}`))
			_, code, ok := module.ImportError(err)
			if !ok || code != "conflicting_field" {
				t.Fatal("nested TLS", reverse, err)
			}
		}
	}
	// Equal TLS aliases use complete, valid shared trust settings.
	m := testkit.TLS(t)
	b, _ := json.Marshal(m)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(b, &fields)
	for _, key := range []string{"server_name", "certificate_file", "private_key_file", "ca_certificate"} {
		tls, _ := json.Marshal(fields)
		tls = append(tls[:len(tls)-1], []byte(`,"`+strings.ToUpper(key)+`":`+string(fields[key])+`}`)...)
		if _, err := module.Decode([]byte(`{"security":"tls","tls":` + string(tls) + `}`)); err != nil {
			t.Fatal("equal nested TLS", key, err)
		}
	}
	for _, reverse := range []bool{false, true} {
		a, b := `"uuid":"`+syntheticUUID+`"`, `"UUID":"00000000-0000-1000-8000-000000000002"`
		if reverse {
			a, b = b, a
		}
		doc := `{"schema":1,"name":"synthetic","listener":{"host":"127.0.0.1","port":443},"display_endpoint":{"host":"localhost","port":443},"settings":{},"users":[{"account_name":"synthetic",` + a + `,` + b + `}]}`
		_, err := (module.Module{}).DecodeCreation([]byte(doc))
		_, code, ok := module.ImportError(err)
		if !ok || code != "conflicting_field" {
			t.Fatal("credential aliases", err)
		}
		if strings.Contains(err.Error(), syntheticUUID) {
			t.Fatal("credential leaked")
		}
		same := strings.ReplaceAll(doc, "00000000-0000-1000-8000-000000000002", syntheticUUID)
		if _, err := (module.Module{}).DecodeCreation([]byte(same)); err != nil {
			t.Fatal("equal credential alias", reverse, err)
		}
	}
	for _, pair := range []string{`"sni":"first.test","servername":"second.test"`, `"sni":"same.test","servername":"same.test"`, `"sni":"","servername":""`} {
		parts := strings.Split(pair, ",")
		for _, reverse := range []bool{false, true} {
			p := parts[0] + "," + parts[1]
			if reverse {
				p = parts[1] + "," + parts[0]
			}
			body := `{"proxies":[{"type":"vmess","name":"synthetic","server":"localhost","port":443,"uuid":"` + syntheticUUID + `","tls":true,` + p + `}]}`
			result, err := nodeimport.Parse("mihomo", []byte(body))
			if err != nil || len(result.Issues) != 1 || result.Issues[0].Code != "conflicting_field" {
				t.Fatal("SNI aliases", reverse, err, result.Issues)
			}
		}
	}
}

func TestReviewFix1TypedErrorWrapping(t *testing.T) {
	for _, e := range []error{module.ConflictingField(), module.InvalidCredential(), module.Unsupported("unsupported_legacy_vmess"), module.Unsupported("unsupported_transport"), module.Unsupported("unsupported_security")} {
		wrapped := fmt.Errorf("synthetic validation: %w", e)
		k, c, ok := module.ImportError(wrapped)
		if !ok || k == "" || c == "" {
			t.Fatal("wrapped cause lost", wrapped)
		}
		var domain *identity.Error
		if !errors.As(wrapped, &domain) {
			t.Fatal("existing domain contract lost")
		}
	}
}
