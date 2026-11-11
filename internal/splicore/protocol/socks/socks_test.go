package socks

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"testing"
)

func TestPipelinedGreetingRequestAndPayload(t *testing.T) {
	b, _ := hex.DecodeString("0502020005010001c000020101bb7061796c6f6164")
	r := bytes.NewReader(b)
	var response bytes.Buffer
	if err := AcceptAuth(r, &response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response.Bytes(), []byte{5, 0}) {
		t.Fatal("greeting wire")
	}
	command, dst, err := ReadCommand(r)
	if err != nil || command != Connect || dst.Host != "192.0.2.1" || dst.Port != 443 {
		t.Fatal(command, dst, err)
	}
	p, _ := io.ReadAll(r)
	if string(p) != "payload" {
		t.Fatal("pipelined payload consumed")
	}
	response.Reset()
	if err := Respond(&response, Succeeded, &net.UDPAddr{IP: net.IPv4zero}); err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("05000001000000000000")
	if !bytes.Equal(response.Bytes(), want) {
		t.Fatal("reply wire")
	}
}

func TestRejectUnacceptedAuthAndReservedByte(t *testing.T) {
	var response bytes.Buffer
	if err := AcceptAuth(bytes.NewReader([]byte{5, 1, 2}), &response); err == nil {
		t.Fatal("accepted unsupported auth")
	}
	if !bytes.Equal(response.Bytes(), []byte{5, 255}) {
		t.Fatal("auth rejection response")
	}
	if _, _, err := ReadCommand(bytes.NewReader([]byte{5, 1, 1, 1, 127, 0, 0, 1, 0, 80})); err == nil {
		t.Fatal("accepted nonzero reserved byte")
	}
}

func FuzzSOCKSCommand(f *testing.F) {
	f.Add([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80})
	f.Add([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		r := bytes.NewReader(b)
		_, dst, err := ReadCommand(r)
		if err == nil && len(dst.Host) > 253 {
			t.Fatal("unbounded host")
		}
	})
}
