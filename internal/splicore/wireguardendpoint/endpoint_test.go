//go:build with_gvisor

package wireguardendpoint

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

type echoDispatcher struct {
	mu         sync.Mutex
	identities []Identity
}

func (d *echoDispatcher) record(ctx context.Context) {
	id, ok := PeerIdentity(ctx)
	if !ok {
		panic("missing authenticated identity")
	}
	d.mu.Lock()
	d.identities = append(d.identities, id)
	d.mu.Unlock()
}

func (d *echoDispatcher) TCP(ctx context.Context, c net.Conn, _, _ netip.AddrPort) {
	d.record(ctx)
	_, _ = io.Copy(c, c)
}

func (d *echoDispatcher) UDP(ctx context.Context, c net.Conn, _, _ netip.AddrPort) {
	d.record(ctx)
	b := make([]byte, 65535)
	for {
		n, err := c.Read(b)
		if err != nil {
			return
		}
		if _, err = c.Write(b[:n]); err != nil {
			return
		}
	}
}

func testKeys(t *testing.T) (E.Secret, string) {
	t.Helper()
	private, public, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := E.ParseSecret(private)
	if err != nil {
		t.Fatal(err)
	}
	return secret, public
}

func pair(t *testing.T, psk bool) (*Endpoint, *Endpoint, *echoDispatcher, *echoDispatcher) {
	t.Helper()
	ka, pa := testKeys(t)
	kb, pb := testKeys(t)
	aconfig := E.WireGuard{Tag: "a", PrivateKey: ka, Addresses: []string{"10.34.0.1/32", "fd34::1/128"}, Peers: []E.WireGuardPeer{{PublicKey: pb, AllowedIPs: []string{"10.34.0.2/32", "fd34::2/128"}}}}
	bconfig := E.WireGuard{Tag: "b", PrivateKey: kb, Addresses: []string{"10.34.0.2/32", "fd34::2/128"}, Peers: []E.WireGuardPeer{{PublicKey: pa, AllowedIPs: []string{"10.34.0.1/32", "fd34::1/128"}}}}
	if psk {
		key, _ := testKeys(t)
		aconfig.Peers[0].PreSharedKey = key
		bconfig.Peers[0].PreSharedKey = key
	}
	da, db := &echoDispatcher{}, &echoDispatcher{}
	b, err := New(context.Background(), bconfig, Options{Dispatcher: db, Underlay: underlay.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	})
	if err = b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	aconfig.Peers[0].Endpoint = net.JoinHostPort("127.0.0.1", itoa(b.Status().ListenPort))
	a, err := New(context.Background(), aconfig, Options{Dispatcher: da, Underlay: underlay.New()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := a.Close(); err != nil {
			t.Error(err)
		}
	})
	if err = a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, b, da, db
}
func itoa(port int) string { return strconv.Itoa(port) }
func transferTCP(t *testing.T, e *Endpoint, ip string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := e.DialContext(ctx, access.Endpoint{Host: ip, Port: 12345})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte("wireguard"), 400)
	if _, err = c.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("TCP payload: bytes=%d err=%v", len(got), err)
	}
}

func transferUDP(t *testing.T, e *Endpoint, ip string, size int) {
	t.Helper()
	target := access.Endpoint{Host: ip, Port: 12346}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := e.ListenPacket(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte("u"), size)
	destination := net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(ip), target.Port))
	if _, err = c.WriteTo(payload, destination); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, size+1)
	n, source, err := c.ReadFrom(got)
	if err != nil || !bytes.Equal(got[:n], payload) || source.String() != destination.String() {
		t.Fatalf("UDP bytes=%d source=%v err=%v", n, source, err)
	}
}

func TestWireGuardDualStackBothDirections(t *testing.T) {
	for _, psk := range []bool{false, true} {
		name := "no-psk"
		if psk {
			name = "matching-psk"
		}
		t.Run(name, func(t *testing.T) {
			a, b, da, db := pair(t, psk)
			for _, ip := range []string{"10.34.0.2", "fd34::2"} {
				t.Run("a-to-b-"+ip, func(t *testing.T) {
					transferTCP(t, a, ip)
					size := 1392
					if ip == "fd34::2" {
						size = 1372
					}
					transferUDP(t, a, ip, size)
				})
			}
			for _, ip := range []string{"10.34.0.1", "fd34::1"} {
				t.Run("b-to-a-"+ip, func(t *testing.T) { transferTCP(t, b, ip); transferUDP(t, b, ip, 512) })
			}
			for _, entry := range []struct {
				e    *Endpoint
				d    *echoDispatcher
				tag  string
				peer string
			}{{a, da, "a", a.config.Peers[0].PublicKey}, {b, db, "b", b.config.Peers[0].PublicKey}} {
				entry.d.mu.Lock()
				if len(entry.d.identities) == 0 {
					t.Error("no inbound identities")
				}
				for _, id := range entry.d.identities {
					if id.EndpointTag != entry.tag || id.PeerPublicKey != entry.peer {
						t.Error("wrong credential identity")
					}
				}
				entry.d.mu.Unlock()
				status := entry.e.Status()
				if status.Peers[0].LastHandshake.IsZero() || status.Peers[0].RXBytes == 0 || status.Peers[0].TXBytes == 0 {
					t.Fatalf("missing operational status: %+v", status)
				}
			}
		})
	}
}
