package wire

import (
	"bytes"
	"encoding/hex"
	"io"
	"strings"
	"testing"
)

type oneByte struct{ io.Reader }

func (r oneByte) Read(b []byte) (int, error) {
	if len(b) > 1 {
		b = b[:1]
	}
	return r.Reader.Read(b)
}
func TestWireGoldenEndianAndFragmentation(t *testing.T) {
	golden, _ := hex.DecodeString("02112233440003616263")
	b, err := AppendFrame(nil, Frame{Command: Data, Stream: 0x11223344, Payload: []byte("abc")})
	if err != nil || !bytes.Equal(b, golden) {
		t.Fatal("frame differs from public byte layout")
	}
	f, err := ReadFrame(oneByte{bytes.NewReader(golden)})
	if err != nil || f.Command != Data || f.Stream != 0x11223344 || string(f.Payload) != "abc" {
		t.Fatal("fragmented read", err)
	}
	joined := append(append([]byte{}, golden...), golden...)
	reader := bytes.NewReader(joined)
	for range 2 {
		if _, err := ReadFrame(reader); err != nil {
			t.Fatal(err)
		}
	}
	if reader.Len() != 0 {
		t.Fatal("coalesced frame bytes lost")
	}
}
func TestAuthenticationGoldenCompletePaddingAndIdentity(t *testing.T) {
	key := PasswordKey("password")
	if hex.EncodeToString(key[:]) != "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" {
		t.Fatal("SHA256 authentication")
	}
	b, _ := Authentication(key, []byte{1, 2, 3})
	if b[32] != 0 || b[33] != 3 || len(b) != 37 {
		t.Fatal("padding length endian")
	}
	r := bytes.NewReader(append(b, 99))
	got, err := ReadAuthentication(oneByte{r})
	if err != nil || got != key || r.Len() != 1 {
		t.Fatal("auth padding not fully consumed", err)
	}
	users := map[AuthKey]string{key: "binding-A", PasswordKey("other-password"): "binding-B"}
	if id, ok := Match(key, users); !ok || id != "binding-A" {
		t.Fatal("wrong account identity")
	}
	if _, ok := Match(PasswordKey("unknown"), users); ok {
		t.Fatal("anonymous authentication")
	}
	for n := 0; n < len(b); n++ {
		if _, err := ReadAuthentication(bytes.NewReader(b[:n])); err == nil {
			t.Fatal("truncated auth accepted", n)
		}
	}
	if _, err := Authentication(key, make([]byte, MaxPayload+1)); err == nil {
		t.Fatal("oversized auth padding")
	}
}
func TestSettingsOptionalFieldsAndMalformed(t *testing.T) {
	settings, err := ParseSettings([]byte("v=2\nclient=\npadding-md5=00000000000000000000000000000000\noptional=value=with=equals\n"))
	if err != nil || Version(settings) != 2 || settings["optional"] != "value=with=equals" {
		t.Fatal("valid optional settings", err)
	}
	for _, bad := range []string{"", "client=x", "v=0", "v=-1", "v=+2", "v=65536", "v=2\nv=1", "v=2\nbroken", "v=2\n=empty", "v=2\r\n", "v=2\n\n", strings.Repeat("x", MaxSettings+1), "v=2\nclient=\xff"} {
		if _, err := ParseSettings([]byte(bad)); err == nil {
			t.Fatal("malformed settings accepted")
		}
	}
}
func TestFrameMalformedAndResourceBounds(t *testing.T) {
	for command := byte(0); command <= ServerSettings; command++ {
		f := Frame{Command: command}
		if command == Data {
			f.Stream = 1
			f.Payload = []byte("x")
		}
		b, _ := AppendFrame(nil, f)
		if _, err := ReadFrame(bytes.NewReader(b)); err != nil {
			t.Fatal("wire command", command, err)
		}
		for n := 0; n < len(b); n++ {
			if _, err := ReadFrame(bytes.NewReader(b[:n])); err == nil {
				t.Fatal("truncated frame", command, n)
			}
		}
	}
	for _, bad := range [][]byte{{11, 0, 0, 0, 0, 0, 0}, {Open, 0, 0, 0, 1, 0, 1, 42}, {Settings, 0, 0, 0, 0, 0x20, 1}, {Alert, 0, 0, 0, 0, 4, 1}, {Heartbeat, 0, 0, 0, 0, 0, 1, 0}} {
		if _, err := ReadFrame(bytes.NewReader(bad)); err == nil {
			t.Fatal("invalid command or bounded length accepted")
		}
	}
	b, _ := AppendFrame(nil, Frame{Command: Data, Stream: 1, Payload: make([]byte, MaxPayload)})
	if f, err := ReadFrame(bytes.NewReader(b)); err != nil || len(f.Payload) != MaxPayload {
		t.Fatal("maximum legal frame", err)
	}
	if _, err := AppendFrame(nil, Frame{Command: Data, Payload: make([]byte, MaxPayload+1)}); err == nil {
		t.Fatal("frame overflow")
	}
}

type stalledWriter struct{}

func (stalledWriter) Write([]byte) (int, error) { return 0, nil }
func TestWriterNoProgressBound(t *testing.T) {
	if WriteAll(stalledWriter{}, []byte("x")) != io.ErrNoProgress {
		t.Fatal("no-progress writer")
	}
}
