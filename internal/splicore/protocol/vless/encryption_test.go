package vless

import (
	"encoding/json"
	"testing"

	"github.com/ike-sh/Splicore/protocol/vless/encryption"
)

func TestEncryptionCreationAndStrictBoundaries(t *testing.T) {
	private, public, e := encryption.Generate("x25519", "random", "0rtt", "600s", "100-35-35")
	if e != nil {
		t.Fatal(e)
	}
	base := map[string]any{"schema": 1, "name": "encrypted", "listener": map[string]any{"host": "127.0.0.1", "port": 443}, "display_endpoint": map[string]any{"host": "example.test", "port": 443}, "settings": map[string]any{"security": "none", "flow": string(Vision), "transport": "tcp", "packet_encoding": "xudp"}, "server_secret": map[string]any{"decryption": private}, "users": []any{map[string]any{"account_name": "Alpha"}}}
	data, _ := json.Marshal(base)
	draft, e := (Module{}).DecodeCreation(data)
	if e != nil {
		t.Fatal("Vision encryption with no outer security", e)
	}
	settings, e := Decode(draft.Settings)
	if e != nil || settings.Encryption != public || len(draft.ServerPayloads) != 1 {
		t.Fatal("secret/public projection", e)
	}
	for _, mutate := range []func(map[string]any){
		func(d map[string]any) { d["fallbacks"] = []any{map[string]any{"dest": 80}} },
		func(d map[string]any) {
			d["settings"].(map[string]any)["fallbacks"] = []any{map[string]any{"dest": 80}}
		},
		func(d map[string]any) { d["settings"].(map[string]any)["encryption"] = "" },
		func(d map[string]any) { d["settings"].(map[string]any)["encryption"] = nil },
		func(d map[string]any) { d["settings"].(map[string]any)["Encryption"] = public },
		func(d map[string]any) { d["settings"].(map[string]any)["encryption"] = "none" },
		func(d map[string]any) {
			delete(d, "server_secret")
			d["settings"].(map[string]any)["encryption"] = public
		},
	} {
		var candidate map[string]any
		_ = json.Unmarshal(data, &candidate)
		mutate(candidate)
		b, _ := json.Marshal(candidate)
		if _, e := (Module{}).DecodeCreation(b); e == nil {
			t.Fatal("invalid encrypted creation accepted")
		}
	}
	for _, b := range []string{`{"security":"none","flow":"none","packet_encoding":"xudp","encryption":""}`, `{"security":"none","flow":"none","packet_encoding":"xudp","encryption":null}`, `{"security":"none","flow":"none","packet_encoding":"xudp","Encryption":"none"}`} {
		if _, e := DecodeClientOptions([]byte(b)); e == nil {
			t.Fatal("ambiguous encryption option")
		}
	}
	if _, e := DecodeClientOptions([]byte(`{"security":"none","flow":"none","packet_encoding":"xudp"}`)); e != nil {
		t.Fatal("historical omission", e)
	}
}
