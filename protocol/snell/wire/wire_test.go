package wire

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

const testPSK = "SyntheticSnellWire12345"

func keyFor(t testing.TB, v int) *Key {
	t.Helper()
	k, e := NewKey(v, testPSK)
	if e != nil {
		t.Fatal(e)
	}
	return k
}

func TestRecordsOwnPayloadAndAuthenticatedBounds(t *testing.T) {
	for _, version := range []int{4, 5, 6} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			key := keyFor(t, version)
			var wire bytes.Buffer
			e := NewEncoder(&wire, key)
			original := bytes.Repeat([]byte("owned-record"), 16000)
			if n, err := e.Write(original); err != nil || n != len(original) {
				t.Fatalf("write %d %v", n, err)
			}
			if err := e.Record(nil); err != nil {
				t.Fatal(err)
			}
			encoded := bytes.Clone(wire.Bytes())
			d := NewDecoder(&wire, key)
			var got, first []byte
			for {
				p, err := d.Next()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if first == nil {
					first = p
				}
				got = append(got, p...)
			}
			if !bytes.Equal(original, got) || !bytes.Equal(first, original[:len(first)]) {
				t.Fatal("payload corruption or aliased record allocation")
			}
			bad := bytes.Clone(encoded)
			bad[len(bad)/2] ^= 1
			d = NewDecoder(bytes.NewReader(bad), key)
			for {
				_, err := d.Next()
				if err != nil {
					if errors.Is(err, io.EOF) {
						t.Fatal("corruption accepted")
					}
					break
				}
			}
			wrong, _ := NewKey(version, "WrongSyntheticKey12345")
			if _, err := NewDecoder(bytes.NewReader(encoded), wrong).Next(); err == nil {
				t.Fatal("wrong key accepted")
			}
		})
	}
}

func TestReusableTransportPreservesHalfCloseResponse(t *testing.T) {
	for _, version := range []int{5, 6} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			_ = a.SetDeadline(time.Now().Add(10 * time.Second))
			_ = b.SetDeadline(time.Now().Add(10 * time.Second))
			key := keyFor(t, version)
			done := make(chan error, 1)
			go func() {
				done <- Serve(b, key, func(c *Tunnel, dst access.Endpoint) error {
					if dst.Host != "example.test" || dst.Port != 443 {
						return ErrFrame
					}
					p, e := io.ReadAll(c)
					if e != nil {
						return e
					}
					_, e = c.Write(p)
					return e
				}, func(*Packet) error { return ErrFrame })
			}()
			w, r := NewEncoder(a, key), NewDecoder(a, key)
			for round := range 10 {
				payload := bytes.Repeat([]byte{byte(round), 42}, 2048)
				q, _ := EncodeRequest(Request{Command: 5, Destination: access.Endpoint{Host: "example.test", Port: 443}})
				if _, e := w.Write(append(q, payload...)); e != nil {
					t.Fatal(e)
				}
				if e := w.Record(nil); e != nil {
					t.Fatal(e)
				}
				var got []byte
				for first := true; ; first = false {
					p, e := r.Next()
					if errors.Is(e, io.EOF) {
						break
					}
					if e != nil {
						t.Fatal(e)
					}
					if first {
						p, e = tunnelReply(p)
						if e != nil {
							t.Fatal(e)
						}
					}
					got = append(got, p...)
				}
				if !bytes.Equal(payload, got) {
					t.Fatal("half-close lost response or reuse mixed requests")
				}
			}
			_ = a.Close()
			<-done
		})
	}
}

func TestPacketWriteProgressesWithPendingRead(t *testing.T) {
	for _, v := range []int{4, 6} {
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			_ = a.SetDeadline(time.Now().Add(5 * time.Second))
			_ = b.SetDeadline(time.Now().Add(5 * time.Second))
			serverVersion := v
			if v == 4 {
				serverVersion = 5
			}
			done := make(chan error, 1)
			go func() {
				done <- Serve(b, keyFor(t, serverVersion), func(*Tunnel, access.Endpoint) error { return ErrFrame }, func(p *Packet) error {
					data := make([]byte, 65535)
					n, addr, e := p.ReadFrom(data)
					if e != nil {
						return e
					}
					_, e = p.WriteTo(data[:n], addr)
					return e
				})
			}()
			p, e := ClientPacket(a, keyFor(t, v), access.Endpoint{Host: "127.0.0.1", Port: 1234})
			if e != nil {
				t.Fatal(e)
			}
			read := make(chan error, 1)
			go func() {
				b := make([]byte, 65535)
				n, _, e := p.ReadFrom(b)
				if e == nil && !bytes.Equal(b[:n], []byte("duplex")) {
					e = ErrFrame
				}
				read <- e
			}()
			if _, e = p.WriteTo([]byte("duplex"), nil); e != nil {
				t.Fatal(e)
			}
			if e = <-read; e != nil {
				t.Fatal(e)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestTunnelReadWriteCloseBufferOwnership(t *testing.T) {
	key := keyFor(t, 6)
	for range 128 {
		a, b := net.Pipe()
		c, _ := ClientTCP(a, key, access.Endpoint{Host: "127.0.0.1", Port: 1234})
		barrier := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(4)
		go func() { defer wg.Done(); <-barrier; _, _ = io.Copy(io.Discard, c) }()
		go func() { defer wg.Done(); <-barrier; _, _ = c.Write([]byte("owned")) }()
		go func() { defer wg.Done(); <-barrier; _ = c.Close() }()
		go func() { defer wg.Done(); <-barrier; _ = b.Close() }()
		close(barrier)
		wg.Wait()
	}
}

func FuzzRequestAndDatagram(f *testing.F) {
	f.Add([]byte{1, 5, 0, 1, 'a', 0, 80})
	f.Add([]byte{1, 6, 0})
	f.Add([]byte{1, 0, 4, 127, 0, 0, 1, 0, 53, 42})
	f.Fuzz(func(t *testing.T, p []byte) {
		if len(p) > 131072 {
			return
		}
		for _, v := range []int{5, 6} {
			_, _, _ = DecodeRequest(p, v)
		}
		for _, response := range []bool{false, true} {
			dst, payload, e := DecodeDatagram(p, response)
			if e == nil {
				encoded, e := EncodeDatagram(dst, payload, response)
				if e != nil {
					t.Fatal(e)
				}
				a, b, e := DecodeDatagram(encoded, response)
				if e != nil || a != dst || !bytes.Equal(b, payload) {
					t.Fatal("datagram roundtrip")
				}
			}
		}
	})
}
func FuzzAuthenticatedRecords(f *testing.F) {
	for _, v := range []int{4, 5, 6} {
		k, _ := NewKey(v, testPSK)
		var b bytes.Buffer
		_ = NewEncoder(&b, k).Record([]byte{1, 6, 0})
		f.Add(b.Bytes(), v)
	}
	f.Fuzz(func(t *testing.T, p []byte, v int) {
		if len(p) > 131072 {
			return
		}
		if v != 4 && v != 5 && v != 6 {
			return
		}
		k, _ := NewKey(v, testPSK)
		d := NewDecoder(bytes.NewReader(p), k)
		for range 64 {
			if _, e := d.Next(); e != nil {
				break
			}
		}
	})
}
