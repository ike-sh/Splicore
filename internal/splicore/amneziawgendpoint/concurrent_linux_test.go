//go:build linux && with_gvisor

package amneziawgendpoint

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	WG "github.com/ike-sh/Splicore/internal/splicore/wireguardendpoint"
)

type standardWGEcho struct{}

func (standardWGEcho) TCP(ctx context.Context, c net.Conn, _, _ netip.AddrPort) {
	if _, ok := WG.PeerIdentity(ctx); !ok {
		panic("standard WG identity missing")
	}
	if _, ok := PeerIdentity(ctx); ok {
		panic("AWG identity leaked into standard WG")
	}
	_, _ = io.Copy(c, c)
}

func (standardWGEcho) UDP(ctx context.Context, c net.Conn, _, _ netip.AddrPort) {
	if _, ok := WG.PeerIdentity(ctx); !ok {
		panic("standard WG identity missing")
	}
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

func TestAWGAndStandardWGConcurrentIsolation(t *testing.T) {
	for _, mode := range []E.WireGuardBackend{E.Userspace, E.Kernel} {
		t.Run(string(mode), func(t *testing.T) {
			if mode == E.Kernel && os.Getenv("SPLICORE_PHASE36_KERNEL") != "1" {
				t.Skip("standard WG kernel needs isolated CAP_NET_ADMIN qualification")
			}
			ctx := context.Background()
			wk, wp := testKeys(t)
			rk, rp := testKeys(t)
			makeWG := func(c E.WireGuard) *WG.Endpoint {
				t.Helper()
				e, err := WG.New(ctx, c, WG.Options{Dispatcher: standardWGEcho{}, Underlay: underlay.New()})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := e.Close(); err != nil {
						t.Error(err)
					}
				})
				if err = e.Start(ctx); err != nil {
					t.Fatal(err)
				}
				return e
			}
			server := makeWG(E.WireGuard{Tag: "wg-server", Backend: mode, PrivateKey: rk, Addresses: []string{"10.38.0.2/32", "fd38::2/128"}, Peers: []E.WireGuardPeer{{PublicKey: wp, AllowedIPs: []string{"10.38.0.1/32", "fd38::1/128"}}}})
			client := makeWG(E.WireGuard{Tag: "wg-client", Backend: mode, PrivateKey: wk, Addresses: []string{"10.38.0.1/32", "fd38::1/128"}, Peers: []E.WireGuardPeer{{PublicKey: rp, AllowedIPs: []string{"10.38.0.2/32", "fd38::2/128"}, Endpoint: net.JoinHostPort("127.0.0.1", itoa(server.Status().ListenPort))}}})
			var pairs [][2]*Endpoint
			for i, profile := range []string{"D", "I"} {
				ck, cp := testKeys(t)
				sk, sp := testKeys(t)
				a, b := qualificationProfile(profile), qualificationProfile(profile)
				// Distinct keys and parameter sets coexist on the same inner addresses.
				a.Tag, a.PrivateKey, a.Addresses = "awg-client", ck, []string{"10.36.0.1/32", "fd36::1/128"}
				b.Tag, b.PrivateKey, b.Addresses = "awg-server", sk, []string{"10.36.0.2/32", "fd36::2/128"}
				b.Peers = []E.WireGuardPeer{{PublicKey: cp, AllowedIPs: a.Addresses}}
				if i == 1 {
					a.HeaderProtectionKey, _ = testKeys(t)
					b.HeaderProtectionKey = a.HeaderProtectionKey
				}
				peer := performanceEndpoint(t, b)
				a.Peers = []E.WireGuardPeer{{PublicKey: sp, Endpoint: net.JoinHostPort("127.0.0.1", itoa(peer.Status().ListenPort)), AllowedIPs: b.Addresses}}
				pairs = append(pairs, [2]*Endpoint{performanceEndpoint(t, a), peer})
			}
			var workers sync.WaitGroup
			workers.Go(func() {
				for range 10 {
					mixedExchange(t, client, "10.38.0.2")
					mixedExchange(t, client, "fd38::2")
				}
			})
			for _, pair := range pairs {
				workers.Go(func() {
					for range 10 {
						transferTCP(t, pair[0], "10.36.0.2")
						transferUDP(t, pair[1], "fd36::1", 1024)
					}
				})
			}
			workers.Wait()
			for _, pair := range pairs {
				closedStatus(t, pair[0])
				closedStatus(t, pair[1])
			}
			// Closing and replacing AWG engines cannot affect an active WG pair.
			mixedExchange(t, client, "fd38::2")
			if client.Status().Selected != mode || client.Status().Peers[0].LastHandshake.IsZero() {
				t.Fatal("standard WG backend changed")
			}
		})
	}
}

func mixedExchange(t *testing.T, e ports.ClientDialer, ip string) {
	t.Helper()
	target := access.Endpoint{Host: ip, Port: 12345}
	c, err := e.DialContext(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("separate WireGuard identity")
	if _, err = c.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("standard WG stream isolation", err)
	}
	p, err := e.(ports.ClientPacketDialer).ListenPacket(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	_ = p.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = p.WriteTo(payload, net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(ip), target.Port))); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, _, err := p.ReadFrom(buf)
	if err != nil || !bytes.Equal(buf[:n], payload) {
		t.Fatal("standard WG datagram isolation", err)
	}
}
