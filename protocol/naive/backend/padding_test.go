package backend

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

type memoryConn struct {
	reader  io.Reader
	written bytes.Buffer
	closed  bool
	chunk   int
}

func (c *memoryConn) Read(p []byte) (int, error) {
	if c.chunk > 0 {
		p = p[:min(c.chunk, len(p))]
	}
	return c.reader.Read(p)
}
func (c *memoryConn) Write(p []byte) (int, error)      { return c.written.Write(p) }
func (c *memoryConn) Close() error                     { c.closed = true; return nil }
func (c *memoryConn) LocalAddr() net.Addr              { return streamAddr("local") }
func (c *memoryConn) RemoteAddr() net.Addr             { return streamAddr("remote") }
func (c *memoryConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryConn) SetWriteDeadline(time.Time) error { return nil }

func TestNaivePaddingBoundariesAndIncrementalReads(t *testing.T) {
	for _, length := range []int{1, 65534, 65535, 65536, 2 * 65535, 9 * 65535, 3 << 20} {
		for _, chunk := range []int{0, 1, 2, 7, 65536} {
			t.Run(fmt.Sprintf("%d/read-%d", length, chunk), func(t *testing.T) {
				payload := bytes.Repeat([]byte{0x93}, length)
				raw := &memoryConn{reader: bytes.NewReader(nil)}
				writer := paddedWithRandom(raw, bytes.NewReader(bytes.Repeat([]byte{255}, FirstPaddings)))
				n, err := writer.Write(payload)
				if err != nil || n != len(payload) {
					t.Fatalf("write %d %v", n, err)
				}
				reader := Padded(&memoryConn{reader: bytes.NewReader(raw.written.Bytes()), chunk: chunk})
				decoded, err := io.ReadAll(reader)
				if err != nil || !bytes.Equal(payload, decoded) {
					t.Fatalf("payload length %d != %d: %v", len(payload), len(decoded), err)
				}
				if writer.writes != min(FirstPaddings, (length+MaxPayload-1)/MaxPayload) {
					t.Fatal("wrong record count")
				}
			})
		}
	}
}
func TestNaivePaddingIndependentDirectionsAndRawTransition(t *testing.T) {
	raw := &memoryConn{reader: bytes.NewReader(nil)}
	writer := paddedWithRandom(raw, bytes.NewReader(bytes.Repeat([]byte{0}, 8)))
	for range 8 {
		if _, err := writer.Write([]byte("p")); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = writer.Write([]byte("raw-tail"))
	encoded := append([]byte(nil), raw.written.Bytes()...)
	if !bytes.HasSuffix(encoded, []byte("raw-tail")) {
		t.Fatal("raw transition")
	}
	duplexRaw := &memoryConn{reader: bytes.NewReader(encoded), chunk: 1}
	duplex := paddedWithRandom(duplexRaw, bytes.NewReader([]byte{9}))
	decoded, err := io.ReadAll(duplex)
	if err != nil || string(decoded) != "ppppppppraw-tail" {
		t.Fatal(string(decoded), err)
	}
	if duplex.writes != 0 || duplex.reads != 8 {
		t.Fatal("shared direction counter")
	}
	_, err = duplex.Write([]byte("independent"))
	if err != nil || duplexRaw.written.Bytes()[2] != 9 {
		t.Fatal("write padding incorrectly disabled")
	}
}
func TestNaivePaddingZeroRecordsArbitraryPaddingAndMalformedEOF(t *testing.T) {
	t.Run("arbitrary-padding", func(t *testing.T) {
		raw := []byte{0, 1, 3, 'x', 1, 2, 3}
		got, err := io.ReadAll(Padded(&memoryConn{reader: bytes.NewReader(raw), chunk: 1}))
		if err != nil || string(got) != "x" {
			t.Fatal(got, err)
		}
	})
	t.Run("zero-records", func(t *testing.T) {
		raw := append(make([]byte, 8*3), []byte("raw")...)
		got, err := io.ReadAll(Padded(&memoryConn{reader: bytes.NewReader(raw)}))
		if err != nil || string(got) != "raw" {
			t.Fatal(got, err)
		}
	})
	for name, raw := range map[string][]byte{"one-byte-header": {1}, "two-byte-header": {0, 1}, "missing-data": {0, 2, 0, 'x'}, "missing-padding": {0, 1, 2, 'x', 0}, "max-declared-truncated": {255, 255, 255}} {
		t.Run(name, func(t *testing.T) {
			_, err := io.ReadAll(Padded(&memoryConn{reader: bytes.NewReader(raw), chunk: 1}))
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("expected bounded truncation: %v", err)
			}
		})
	}
}
func TestNaivePaddingUniformByteRangeAndZeroFill(t *testing.T) {
	for value := 0; value <= 255; value++ {
		raw := &memoryConn{reader: bytes.NewReader(nil)}
		conn := paddedWithRandom(raw, bytes.NewReader([]byte{byte(value)}))
		_, err := conn.Write([]byte{7})
		frame := raw.written.Bytes()
		if err != nil || len(frame) != 4+value || binary.BigEndian.Uint16(frame[:2]) != 1 || int(frame[2]) != value || !bytes.Equal(frame[4:], make([]byte, value)) {
			t.Fatal(value, err)
		}
	}
}
