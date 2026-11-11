package testkit

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// ClientHello captures the real standard-library first flight without a socket
// or TLS peer. No certificate verification or network access is performed.
func ClientHello(t testing.TB, name string, version uint16) []byte {
	t.Helper()
	c := &helloCapture{}
	// The capture returns EOF before any peer/certificate exists. Allow an empty
	// server name so tests can capture a real ClientHello without SNI as well.
	client := tls.Client(c, &tls.Config{ServerName: name, MinVersion: version, MaxVersion: version, InsecureSkipVerify: true})
	if err := client.Handshake(); err == nil || c.Len() == 0 {
		t.Fatal("ClientHello capture failed", err)
	}
	return append([]byte(nil), c.Bytes()...)
}

type helloCapture struct{ bytes.Buffer }

func (*helloCapture) Read([]byte) (int, error)         { return 0, io.EOF }
func (*helloCapture) Close() error                     { return nil }
func (*helloCapture) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*helloCapture) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*helloCapture) SetDeadline(time.Time) error      { return nil }
func (*helloCapture) SetReadDeadline(time.Time) error  { return nil }
func (*helloCapture) SetWriteDeadline(time.Time) error { return nil }
