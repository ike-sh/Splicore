//go:build with_quic && with_utls

package application_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	P "github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
	"github.com/sagernet/sing-box/internal/splicore/engine/native"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	mm "github.com/sagernet/sing-box/internal/splicore/protocol/mieru"
	vm "github.com/sagernet/sing-box/internal/splicore/protocol/vless"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	"github.com/sagernet/sing-box/internal/splicore/testkit"
	"github.com/sagernet/sing-box/internal/splicore/underlay"
)

func TestUnderlayActualNativeClientAndServerSocketPaths(t *testing.T) {
	x := testkit.NewUnderlay(t)
	mode, e := x.Factory.Begin(context.Background(), true)
	if e != nil {
		t.Fatal(e)
	}
	defer mode.Close()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, phase8Protocols, x.Factory)
	defer stop(t, s, store)
	cases := expansionCases(t)
	mieruUDP := cases[len(cases)-1]
	mieruUDP.name, mieruUDP.transport = "mieru-udp", "udp"
	mieruUDP.settings, mieruUDP.options = mm.Settings{Transport: "udp", MTU: 1500, Multiplex: "default"}, []byte(`{"transport":"udp"}`)
	material := testkit.TLS(t)
	key, public, e := vm.GenerateServerKey()
	if e != nil {
		t.Fatal(e)
	}
	realitySettings := vm.Settings{Security: vm.Reality, Flow: vm.NoFlow, Transport: "tcp", PacketEncoding: "xudp", Reality: &vm.RealitySettings{PublicKey: public, ServerName: "target.synthetic.test", Target: underlayRealityTarget(t), ShortIDs: []vm.ShortID{"abcd"}}}
	cases = append(cases, mieruUDP,
		expansionCase{"vless-tls", vm.Key(vm.TLS), vm.Settings{Security: vm.TLS, Flow: vm.NoFlow, Transport: "tcp", PacketEncoding: "xudp", TLS: &material}, []byte(`{"security":"tls","flow":"none","packet_encoding":"xudp"}`), "tcp", client.Security{Kind: "tls", TLS: access.ClientTLS{Enabled: true, ServerName: material.ServerName, Trust: "explicit_ca", CACertificate: material.CACertificate}}, native.VLESSOutboundFactory{}},
		expansionCase{"vless-reality", vm.Key(vm.Reality), realitySettings, []byte(`{"security":"reality","flow":"none","packet_encoding":"xudp"}`), "tcp", client.Security{Kind: "reality", TLS: access.ClientTLS{Enabled: true, ServerName: "target.synthetic.test", Trust: "reality", RealityPublicKey: string(public), RealityShortID: "abcd"}}, native.VLESSOutboundFactory{}},
	)
	fs := []ports.OutboundFactory{}
	for _, c := range cases[:5] {
		fs = append(fs, c.factory)
	}
	r, e := registry.NewOutbounds(fs...)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.EnableClientRuntime(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	var queries atomic.Int64
	dnsID := networkID(t)
	applyNetwork(t, s, P.Config{Servers: []P.DNSServer{{ID: dnsID, Name: "owned underlay resolver", Type: "udp", Endpoint: appDNS(t, "udp", &queries), Detour: P.Action{Kind: P.Direct}}}, DNS: P.DNSProfile{Enabled: true, DefaultServer: dnsID, BootstrapServer: dnsID, Strategy: "ipv4_only", TimeoutSeconds: 2, Cache: P.DNSCachePolicy{Capacity: 8}}})
	tcp := echoTarget(t, "127.0.0.1")
	udp := expansionUDP(t, "127.0.0.1")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			beforeProxy, beforeServer := x.Backend.Count(underlay.ProxyUnderlay), x.Backend.Count(underlay.ServerTarget)
			port := freePort(t)
			if c.transport == "quic" || c.transport == "udp" {
				port = udpPort(t)
			}
			var created = expansionCreationResult(t, s, c, port, key.Material.Reveal())
			node := expansionNode(t, s, c, access.Endpoint{Host: "127.0.0.1", Port: port}, expansionCredential(t, store, created, 0))
			out := expansionProxy(t, s, node, "native")
			local := freePort(t)
			addLocal(t, s, local, out)
			if e := transfer(local, tcp, []byte("underlay-runtime-echo")); e != nil {
				t.Fatal(e)
			}
			if e := expansionUDPTraffic(local, udp, []byte("underlay-packet-echo")); e != nil {
				t.Fatal(e)
			}
			waitIdle(t, s)
			if x.Backend.Count(underlay.ProxyUnderlay) <= beforeProxy || x.Backend.Count(underlay.ServerTarget) <= beforeServer {
				t.Fatal("actual client/server escaped underlay", c.name)
			}
		})
	}
	// DIRECT uses the same provider after logical selection.
	before := x.Backend.Count(underlay.DirectEgress)
	local := freePort(t)
	addLocal(t, s, local, "direct")
	if e := transfer(local, tcp, []byte("direct-protected")); e != nil {
		t.Fatal(e)
	}
	if e := expansionUDPTraffic(local, udp, []byte("direct-packet")); e != nil {
		t.Fatal(e)
	}
	tcp6, udp6 := echoTarget(t, "::1"), expansionUDP(t, "::1")
	for _, endpoint := range []access.Endpoint{tcp6, {Host: "target.fixture.invalid", Port: tcp.Port}} {
		if e := transfer(local, endpoint, []byte("direct-family-domain")); e != nil {
			t.Fatal(e)
		}
	}
	for _, endpoint := range []access.Endpoint{udp6, {Host: "target.fixture.invalid", Port: udp.Port}} {
		if e := expansionUDPTraffic(local, endpoint, []byte("direct-family-domain-packet")); e != nil {
			t.Fatal(e)
		}
	}
	waitIdle(t, s)
	if x.Backend.Count(underlay.DirectEgress) <= before {
		t.Fatal("DIRECT escaped factory")
	}
	var proxyUDP bool
	for _, event := range x.Backend.SnapshotEvents() {
		if event.Scope.Purpose == underlay.ProxyUnderlay && (event.Network == "udp" || event.Network == "udp4" || event.Network == "udp6") {
			proxyUDP = true
		}
	}
	if !proxyUDP || queries.Load() == 0 {
		t.Fatal("QUIC/UDP or domain path missing")
	}
}

func expansionCreationResult(t *testing.T, s *application.Service, c expansionCase, port uint16, private string) application.CreationResult {
	if c.name == "vless-reality" {
		return applyVLESS(t, s, vlessDoc(t, port, c.settings.(vm.Settings), private))
	}
	return expansionCreation(t, s, c, "127.0.0.1", port)
}

func underlayRealityTarget(t *testing.T) access.Endpoint {
	t.Helper()
	m := testkit.TLSForName(t, "target.synthetic.test")
	cert, err := tls.LoadX509KeyPair(m.CertificateFile, m.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	l, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	connections := map[net.Conn]bool{}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections[c] = true
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.Copy(c, c)
				mu.Lock()
				delete(connections, c)
				mu.Unlock()
			}()
		}
	}()
	t.Cleanup(func() {
		l.Close()
		mu.Lock()
		for c := range connections {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return access.Endpoint{Host: "127.0.0.1", Port: uint16(l.Addr().(*net.TCPAddr).Port)}
}
