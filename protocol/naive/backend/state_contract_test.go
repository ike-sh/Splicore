package backend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Test through Client.Open, without replacing the HTTP stream or its target.
func TestNaiveBodyConnAPIState(t *testing.T) {
	for _, carrier := range []struct{ name, mode string }{{"h2", "https"}, {"h3", "quic"}} {
		t.Run(carrier.name, func(t *testing.T) {
			if carrier.mode == "quic" && !H3Enabled() {
				t.Skip("with_quic required")
			}
			for _, padding := range []string{"off", "enabled"} {
				t.Run(padding, func(t *testing.T) {
					for _, operation := range []string{"close-write-after-close", "repeat-close-write", "write-after-close-write"} {
						t.Run(operation, func(t *testing.T) {
							testNaiveBodyConnAPIState(t, carrier.mode, padding, operation)
						})
					}
				})
			}
		})
	}
}

func testNaiveBodyConnAPIState(t *testing.T, mode, padding, operation string) {
	t.Helper()
	upload := []byte("initial upload")
	response := []byte("response after observed TCP EOF and client API checks")
	uploadRead, uploadEOF := make(chan struct{}), make(chan struct{})
	allowResponse := make(chan struct{})
	var releaseOnce sync.Once
	releaseResponse := func() { releaseOnce.Do(func() { close(allowResponse) }) }
	defer releaseResponse()
	target, targetResult := halfCloseTarget(t, func(peer *net.TCPConn) error {
		got := make([]byte, len(upload))
		if _, err := io.ReadFull(peer, got); err != nil || !bytes.Equal(got, upload) {
			return fmt.Errorf("target upload = %q, err = %v; want %q", got, err, upload)
		}
		close(uploadRead)
		var extra [1]byte
		if n, err := peer.Read(extra[:]); n != 0 || err != io.EOF {
			return fmt.Errorf("target read after exact upload = (%d, %v); want (0, io.EOF)", n, err)
		}
		close(uploadEOF)
		if operation == "close-write-after-close" {
			return nil
		}
		<-allowResponse
		if _, err := writeAll(peer, response); err != nil {
			return fmt.Errorf("target delayed response: %w", err)
		}
		return peer.CloseWrite()
	})

	proxy, tlsConfig, _ := startTestServer(t, mode)
	echo := echoTarget(t, "tcp", "127.0.0.1:0")
	var carrierDials atomic.Int64
	client := newTestClient(t, mode, proxy, tlsConfig, func(cfg *ClientConfig) {
		cfg.Padding = padding
	}, &carrierDials)
	conn := openNaiveStateContractConn(t, client, target)
	raw := conn.(*pooledStream).raw.(*bodyConn)
	finishCalls := 0
	finishWrite := raw.closeWrite
	raw.closeWrite = func() error { finishCalls++; return finishWrite() }
	sibling := openNaiveStateContractConn(t, client, echo)
	if _, err := writeAll(conn, upload); err != nil {
		t.Fatal("write initial upload:", err)
	}
	halfCloseWait(t, uploadRead)

	if operation == "close-write-after-close" {
		if err := conn.Close(); err != nil {
			t.Fatal("full Close:", err)
		}
		if err := conn.CloseWrite(); !errors.Is(err, net.ErrClosed) {
			t.Errorf("CloseWrite after full Close = %v (%T); want net.ErrClosed", err, err)
		}
		halfCloseResult(t, targetResult)
		halfCloseWait(t, uploadEOF)
		t.Logf("target TCP read exact upload (%d bytes), then EOF after full Close", len(upload))
	} else {
		if err := conn.CloseWrite(); err != nil {
			t.Fatal("initial CloseWrite:", err)
		}
		halfCloseWait(t, uploadEOF)
		t.Logf("target TCP read exact upload (%d bytes), then EOF after initial CloseWrite; response still gated", len(upload))

		switch operation {
		case "repeat-close-write":
			if err := conn.CloseWrite(); err != nil {
				t.Errorf("live repeated CloseWrite = %v; want nil", err)
			} else {
				t.Log("live repeated CloseWrite returned nil before the target response")
			}
		case "write-after-close-write":
			if n, err := conn.Write([]byte("must not reach target")); n != 0 || !errors.Is(err, net.ErrClosed) {
				t.Errorf("nonempty Write after CloseWrite = (%d, %v [%T]); want (0, net.ErrClosed)", n, err, err)
			}
		}
		releaseResponse()
		got, err := io.ReadAll(conn)
		if err != nil || !bytes.Equal(got, response) {
			t.Errorf("delayed response = %q, err = %v; want %q followed by EOF", got, err, response)
		} else {
			t.Logf("client read exact delayed target response (%d bytes) through EOF", len(got))
		}
		if err := conn.Close(); err != nil {
			t.Error("full Close after half-close:", err)
		}
		if err := conn.CloseWrite(); !errors.Is(err, net.ErrClosed) {
			t.Errorf("CloseWrite after half-close then full Close = %v (%T); want net.ErrClosed", err, err)
		}
		halfCloseResult(t, targetResult)
	}

	wantFinishes := 1
	if operation == "close-write-after-close" {
		wantFinishes = 0
	}
	if finishCalls != wantFinishes {
		t.Errorf("underlying send completions = %d; want %d", finishCalls, wantFinishes)
	}

	// The sibling was already open when the primary changed state. Also open
	// a fresh stream after completion to prove continued admission on the carrier.
	echoPayload := []byte("sibling still live")
	if _, err := writeAll(sibling, echoPayload); err != nil {
		t.Fatal("sibling write:", err)
	}
	got := make([]byte, len(echoPayload))
	if _, err := io.ReadFull(sibling, got); err != nil || !bytes.Equal(got, echoPayload) {
		t.Fatalf("sibling echo = %q, err = %v; want %q", got, err, echoPayload)
	}
	transfer(t, client, echo, 37)
	if got := carrierDials.Load(); got != 1 {
		t.Fatalf("sibling and fresh stream used %d carriers; want the one original carrier", got)
	}
	t.Log("active sibling and freshly opened stream echoed data on the original carrier (one TCP dial / QUIC socket)")
}

func openNaiveStateContractConn(t *testing.T, client *Client, target string) interface {
	net.Conn
	CloseWrite() error
} {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.Open(ctx, target)
	if err != nil {
		t.Fatal("Client.Open:", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal("SetDeadline:", err)
	}
	half, ok := conn.(interface {
		net.Conn
		CloseWrite() error
	})
	if !ok {
		t.Fatalf("Client.Open returned %T without CloseWrite", conn)
	}
	return half
}
