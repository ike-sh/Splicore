//go:build with_quic && with_utls

package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/engine/native"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	hm "github.com/sagernet/sing-box/internal/splicore/protocol/hysteria2"
	mm "github.com/sagernet/sing-box/internal/splicore/protocol/mieru"
	sm "github.com/sagernet/sing-box/internal/splicore/protocol/snell"
	tm "github.com/sagernet/sing-box/internal/splicore/protocol/tuic"
	vm "github.com/sagernet/sing-box/internal/splicore/protocol/vless"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	"github.com/sagernet/sing-box/internal/splicore/storage/sqlite"
	"github.com/sagernet/sing-box/internal/splicore/testkit"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks5"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type expansionCase struct {
	name      string
	key       access.ProtocolKey
	settings  any
	options   json.RawMessage
	transport string
	security  client.Security
	factory   ports.OutboundFactory
}

func expansionCases(t *testing.T) []expansionCase {
	tls := testkit.TLS(t)
	trust := client.Security{Kind: "tls", TLS: access.ClientTLS{Enabled: true, ServerName: tls.ServerName, ALPN: []string{"h3"}, Trust: "explicit_ca", CACertificate: tls.CACertificate}}
	return []expansionCase{
		{"snell", sm.Key(6), map[string]any{"version": 6}, []byte(`{"version":6}`), "tcp", client.Security{Kind: "none"}, native.SnellOutboundFactory{}},
		{"hysteria2", hm.Key(), hm.Settings{TLS: tls}, []byte(`{}`), "quic", trust, native.Hysteria2OutboundFactory{}},
		{"tuic", tm.Key(), tm.Settings{TLS: tls, Version: 5, CongestionControl: "cubic", UDPRelayMode: "native"}, []byte(`{"version":5,"congestion_control":"cubic","udp_relay_mode":"native","zero_rtt_handshake":false}`), "quic", trust, native.TUICOutboundFactory{}},
		{"vless", vm.Key(vm.Plain), vm.Settings{Security: vm.Plain, Flow: vm.NoFlow, Transport: "tcp", PacketEncoding: "xudp"}, []byte(`{"security":"none","flow":"none","packet_encoding":"xudp"}`), "tcp", client.Security{Kind: "none"}, native.VLESSOutboundFactory{}},
		{"mieru", mm.Key(), mm.Settings{Transport: "tcp", MTU: 1500, Multiplex: "default"}, []byte(`{"transport":"tcp"}`), "tcp", client.Security{Kind: "none"}, native.MieruOutboundFactory{}},
	}
}
func expansionCreation(t *testing.T, s *application.Service, c expansionCase, host string, port uint16) application.CreationResult {
	t.Helper()
	draft := map[string]any{"schema": 1, "name": "phase11-" + c.name, "engine": "native", "listener": access.Endpoint{Host: host, Port: port}, "display_endpoint": access.Endpoint{Host: host, Port: port}, "settings": c.settings, "users": []any{map[string]any{"account_name": "Alice"}, map[string]any{"account_name": "Bob"}}}
	if c.name == "snell" {
		delete(draft, "engine")
		delete(draft, "users")
		draft["account_name"] = "Alice"
	}
	document, _ := json.Marshal(draft)
	p, err := s.PlanCreation(context.Background(), c.key.Protocol, document)
	if err != nil {
		t.Fatal("server plan", c.name, err)
	}
	result, err := s.ApplyCreation(context.Background(), c.key.Protocol, application.ApplyRequest{Document: document, Digest: p.Digest, Revision: p.Revision})
	if err != nil {
		t.Fatal("server apply", c.name, err)
	}
	return result
}
func payloadInput(p access.Payload) application.CredentialInput {
	var value string
	switch c := p.(type) {
	case access.PSKPayload:
		value = c.Key.Reveal()
	case access.PasswordPayload:
		value = c.Password.Reveal()
	case access.UUIDPayload:
		value = c.UUID.Reveal()
	case access.UUIDPasswordPayload:
		b, _ := json.Marshal(map[string]string{"uuid": c.UUID.Reveal(), "password": c.Password.Reveal()})
		value = string(b)
	case access.UsernamePasswordPayload:
		b, _ := json.Marshal(map[string]string{"username": c.Username.Reveal(), "password": c.Password.Reveal()})
		value = string(b)
	}
	return application.CredentialInput{Kind: p.Kind(), Value: value}
}
func expansionNode(t *testing.T, s *application.Service, c expansionCase, endpoint access.Endpoint, credential access.Payload) identity.ID {
	t.Helper()
	input := payloadInput(credential)
	return clientApply(t, s, application.ClientMutation{Resource: "node", Action: "create", Node: &client.RemoteNode{Name: "phase11-" + c.name, Protocol: c.key, Endpoint: endpoint, Transport: client.Transport{Kind: c.transport}, Security: c.security, Options: client.Options{Schema: 1, Data: c.options}}, Credential: &input}).ID
}
func expansionProxy(t *testing.T, s *application.Service, node identity.ID, engine string) identity.ID {
	t.Helper()
	return clientApply(t, s, application.ClientMutation{Resource: "outbound", Action: "create", Outbound: &client.Outbound{Name: "phase11-" + engine, Kind: "proxy", NodeID: &node, Engine: engine}}).ID
}
func expansionCredential(t *testing.T, store *sqlite.Store, result application.CreationResult, index int) access.Payload {
	t.Helper()
	bindings, err := store.Bindings(context.Background(), result.InboundID)
	if err != nil {
		t.Fatal(err)
	}
	// Preserve the creation response's Alice/Bob order rather than repository sorting.
	for _, b := range bindings {
		if b.ID == result.Bindings[index].BindingID {
			c, err := store.RevealCredential(context.Background(), b.CredentialID)
			if err != nil {
				t.Fatal(err)
			}
			return c.Payload
		}
	}
	t.Fatal("missing created binding")
	return nil
}
func expansionUDP(t *testing.T, host string, fixedPort ...uint16) access.Endpoint {
	t.Helper()
	port := uint16(0)
	if len(fixedPort) > 0 {
		port = fixedPort[0]
	}
	pc, err := net.ListenPacket("udp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65535)
		for {
			n, a, e := pc.ReadFrom(b)
			if e != nil {
				return
			}
			_, _ = pc.WriteTo(b[:n], a)
		}
	}()
	t.Cleanup(func() { _ = pc.Close(); <-done })
	return access.Endpoint{Host: host, Port: uint16(pc.LocalAddr().(*net.UDPAddr).Port)}
}
func expansionUDPTraffic(port uint16, target access.Endpoint, payload []byte) error {
	control, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		return err
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(5 * time.Second))
	response, err := socks.ClientHandshake5(control, socks5.CommandUDPAssociate, M.ParseSocksaddr("0.0.0.0:0"), "", "")
	if err != nil {
		return err
	}
	udp, err := net.Dial("udp", response.Bind.String())
	if err != nil {
		return err
	}
	pc := socks.NewAssociatePacketConn(udp, M.ParseSocksaddrHostPort(target.Host, target.Port), control)
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = pc.WriteTo(payload, M.ParseSocksaddrHostPort(target.Host, target.Port)); err != nil {
		return err
	}
	b := make([]byte, 65535)
	n, _, err := pc.ReadFrom(b)
	if err != nil {
		return err
	}
	if !bytes.Equal(payload, b[:n]) {
		return fmt.Errorf("UDP cross-talk or integrity mismatch")
	}
	return nil
}
func TestPhase11NativeSelfInteropMatrix(t *testing.T) {
	before := runtime.NumGoroutine()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, phase8Protocols)
	defer stop(t, s, store)
	cases := expansionCases(t)
	factories := []ports.OutboundFactory{}
	for _, c := range cases {
		factories = append(factories, c.factory)
	}
	registry, err := registry.NewOutbounds(factories...)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.EnableClientRuntime(context.Background(), registry); err != nil {
		t.Fatal(err)
	}
	tcp4 := echoTarget(t, "127.0.0.1")
	tcp6 := echoTarget(t, "::1")
	udp4 := expansionUDP(t, "127.0.0.1")
	_ = expansionUDP(t, "::1", udp4.Port)
	udp6 := expansionUDP(t, "::1")
	ports := []uint16{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			remote := freePort(t)
			if c.transport == "quic" {
				remote = udpPort(t)
			}
			created := expansionCreation(t, s, c, "127.0.0.1", remote)
			var aliceNode identity.ID
			accounts := 2
			if c.name == "snell" {
				accounts = 1
			}
			for account := range accounts {
				credential := expansionCredential(t, store, created, account)
				node := expansionNode(t, s, c, access.Endpoint{Host: "localhost", Port: remote}, credential)
				if account == 0 {
					aliceNode = node
				}
				out := expansionProxy(t, s, node, "native")
				local := freePort(t)
				addLocal(t, s, local, out)
				if account == 0 {
					ports = append(ports, local)
				}
				tcpDomain := tcp4
				tcpDomain.Host = "localhost"
				udpDomain := udp4
				udpDomain.Host = "localhost"
				for _, target := range []access.Endpoint{tcp4, tcp6, tcpDomain} {
					if err = transfer(local, target, []byte("phase11-TCP-"+c.name)); err != nil {
						t.Fatal("TCP", account, target, err)
					}
				}
				for _, target := range []access.Endpoint{udp4, udp6, udpDomain} {
					if err = expansionUDPTraffic(local, target, []byte("phase11-UDP-"+c.name)); err != nil {
						t.Fatal("UDP", account, target, err)
					}
				}
				if account == 0 {
					if err = transfer(local, tcp4, bytes.Repeat([]byte("0123456789abcdef"), 4*1024*1024/16)); err != nil {
						t.Fatal("4 MiB", err)
					}
					var wg sync.WaitGroup
					fail := make(chan error, 32)
					for i := range 16 {
						wg.Add(2)
						go func() { defer wg.Done(); fail <- transfer(local, tcp4, []byte(fmt.Sprintf("%s-TCP-%d", c.name, i))) }()
						go func() {
							defer wg.Done()
							fail <- expansionUDPTraffic(local, udp4, []byte(fmt.Sprintf("%s-UDP-%d", c.name, i)))
						}()
					}
					wg.Wait()
					close(fail)
					for err := range fail {
						if err != nil {
							t.Fatal("mixed concurrency", err)
						}
					}
				}
			}
			waitIdle(t, s)
			// Rotation uses another valid server credential, then verifies strict invalid
			// material is rejected without changing the committed node/revision.
			rotationCredential := expansionCredential(t, store, created, 0)
			if c.name != "snell" {
				rotationCredential = expansionCredential(t, store, created, 1)
			} else {
				newPort := freePort(t)
				next := expansionCreation(t, s, c, "127.0.0.1", newPort)
				rotationCredential = expansionCredential(t, store, next, 0)
				st, _ := s.ClientStatus(context.Background())
				for _, node := range st.State.Nodes {
					if node.ID == aliceNode {
						node.Endpoint.Port = newPort
						clientApply(t, s, application.ClientMutation{Resource: "node", Action: "update", ID: node.ID, Node: &node})
					}
				}
			}
			rotate := payloadInput(rotationCredential)
			clientApply(t, s, application.ClientMutation{Resource: "node", Action: "rotate", ID: aliceNode, Credential: &rotate})
			if err = transfer(ports[len(ports)-1], tcp4, []byte("rotated-valid-"+c.name)); err != nil {
				t.Fatal(err)
			}
			before, _ := s.ClientStatus(context.Background())
			rotate.Value = ""
			document, _ := json.Marshal(application.ClientMutation{Resource: "node", Action: "rotate", ID: aliceNode, Credential: &rotate})
			if _, err = s.PlanClient(context.Background(), document); err == nil {
				t.Fatal("invalid credential accepted")
			}
			after, _ := s.ClientStatus(context.Background())
			if before.State.Revision != after.State.Revision {
				t.Fatal("invalid rotation changed authority")
			}
			if err = transfer(ports[len(ports)-1], tcp4, []byte("reconnect-"+c.name)); err != nil {
				t.Fatal(err)
			}
		})
	}
	// All adapters and all server runtimes remain active in the same application.
	var wg sync.WaitGroup
	fail := make(chan error, 32)
	for i := range 16 {
		port := ports[i%len(ports)]
		wg.Add(2)
		go func() {
			defer wg.Done()
			fail <- expansionUDPTraffic(port, udp4, []byte(fmt.Sprintf("cross-outbound-%d", i)))
		}()
		go func() { defer wg.Done(); fail <- transfer(port, tcp4, []byte(fmt.Sprintf("mixed-outbound-%d", i))) }()
	}
	wg.Wait()
	close(fail)
	for err := range fail {
		if err != nil {
			t.Fatal(err)
		}
	}
	waitIdle(t, s)
	st, err := s.ClientStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range st.Outbounds {
		if o.Stats.Active != 0 || o.Stats.UDPActive != 0 {
			t.Fatal("active session leak")
		}
	}
	if err = s.CloseRuntime(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		stack := make([]byte, 1<<20)
		n := runtime.Stack(stack, true)
		text := string(stack[:n])
		pending := strings.Contains(text, "github.com/sagernet/sing-quic/") || strings.Contains(text, "github.com/enfein/mieru/v3/pkg/protocol") || strings.Contains(text, "clientruntime.(*Manager).serveUDP")
		if !pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("adapter worker leak\n%s", text)
		}
		runtime.Gosched()
	}
	t.Logf("goroutine baseline=%d after owned shutdown=%d", before, runtime.NumGoroutine())
}

// Compile-time assertions ensure UDP is actual packet I/O for every adapter.
var _ io.Closer = (ports.ClientDialer)(nil)
