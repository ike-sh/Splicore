package snell

import "testing"

func TestV4StrictClientServerSeparation(t *testing.T) {
	for _, raw := range []string{`{"VERSION":4}`, `{"version":4,"Reuse":true}`, `{"version":4,"version":4}`, `{"version":4,"obfs_mode":"http","Obfs_Host":"localhost"}`} {
		if _, e := DecodeClient([]byte(raw)); e == nil {
			t.Fatal("noncanonical/duplicate field accepted", raw)
		}
	}
	for _, raw := range []string{`{"version":4}`, `{"version":4,"obfs_mode":"http"}`, `{"version":4,"obfs_mode":"none"}`} {
		if _, e := Decode([]byte(raw)); e != nil {
			t.Fatal(raw, e)
		}
		if _, e := DecodeClient([]byte(raw)); e != nil {
			t.Fatal(raw, e)
		}
	}
	for _, raw := range []string{`{"version":4,"reuse":true,"udp":true,"udp_port":1234}`, `{"version":4,"obfs_mode":"http","obfs_host":"example.org","obfs_uri":"/path?x=1"}`, `{"version":4,"udp":false}`} {
		if _, e := DecodeClient([]byte(raw)); e != nil {
			t.Fatal(raw, e)
		}
		if _, e := Decode([]byte(raw)); e == nil {
			t.Fatal("client-only options accepted inbound", raw)
		}
	}
	for _, raw := range []string{`{}`, `null`, `{"version":null}`, `{"version":"4"}`, `{"version":4.1}`, `{"version":3}`, `{"version":4,"version":5}`, `{"version":4,"reuse":null}`, `{"version":4,"reuse":1}`, `{"version":4,"udp":null}`, `{"version":4,"udp_port":0}`, `{"version":4,"udp_port":-1}`, `{"version":4,"udp_port":65536}`, `{"version":4,"udp":false,"udp_port":1234}`, `{"version":4,"obfs_mode":"tls"}`, `{"version":4,"obfs_mode":null}`, `{"version":4,"obfs_host":"example.org"}`, `{"version":4,"obfs_uri":"/"}`, `{"version":4,"mode":"safe"}`, `{"version":4,"quic":true}`, `{"version":6,"obfs_mode":"none"}`, `{"version":5,"reuse":false}`, `{"version":4} {}`} {
		if _, e := DecodeClient([]byte(raw)); e == nil {
			t.Fatal("invalid accepted", raw)
		}
	}
	for _, host := range []string{"localhost", "test.example", "127.0.0.1", "::1"} {
		if ValidateObfs("http", host, "/hello?q=1") != nil {
			t.Fatal(host)
		}
	}
	for _, host := range []string{"host\r\nInjected: yes", "has space", "host,inject", "user@example.org"} {
		if ValidateObfs("http", host, "/") == nil {
			t.Fatal(host)
		}
	}
	for _, uri := range []string{"https://example.org/", "//example.org/", "/a b", "/a\r\nX: bad", "/a#fragment", "/bad%xx"} {
		if ValidateObfs("http", "localhost", uri) == nil {
			t.Fatal(uri)
		}
	}
	for server, want := range map[int]int{4: 4, 5: 5, 6: 6} {
		got, e := ClientVersion(server)
		if e != nil || got != want {
			t.Fatal(server, got, e)
		}
	}
}
