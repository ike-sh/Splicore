package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/miekg/dns"
)

// Encode the RFC fields independently of the product codec.
func fixtureSOCKSAddress(host string, port uint16) []byte {
	ip := net.ParseIP(host)
	var address []byte
	switch {
	case ip == nil:
		address = append([]byte{3, byte(len(host))}, host...)
	case ip.To4() != nil:
		address = append([]byte{1}, ip.To4()...)
	default:
		address = append([]byte{4}, ip.To16()...)
	}
	return binary.BigEndian.AppendUint16(address, port)
}

func fixtureSOCKSUDP(t *testing.T, host string) *net.UDPConn {
	t.Helper()
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	return socket
}

func fixtureUDPAssociate(t *testing.T, control *net.TCPConn, sourcePort uint16) netip.AddrPort {
	t.Helper()
	writeSocksFixture(t, control, append([]byte{5, 3, 0}, fixtureSOCKSAddress("0.0.0.0", sourcePort)...))
	readSocksFixture(t, control, []byte{5, 0, 0, 1})
	var address [6]byte
	if _, err := io.ReadFull(control, address[:]); err != nil {
		t.Fatal(err)
	}
	relay := netip.AddrPortFrom(netip.AddrFrom4([4]byte(address[:4])), binary.BigEndian.Uint16(address[4:]))
	if !relay.Addr().IsLoopback() || relay.Port() == 0 {
		t.Fatal("expected a bound IPv4 loopback relay")
	}
	return relay
}

func fixtureUDPFrame(host string, port uint16, payload []byte) []byte {
	frame := append([]byte{0, 0, 0}, fixtureSOCKSAddress(host, port)...)
	return append(frame, payload...)
}

func fixtureUDPWrite(t *testing.T, from *net.UDPConn, to netip.AddrPort, payload []byte) {
	t.Helper()
	n, err := from.WriteToUDPAddrPort(payload, to)
	if err != nil || n != len(payload) {
		t.Fatalf("UDP write sent %d of %d: %v", n, len(payload), err)
	}
}

func fixtureUDPRead(t *testing.T, receiver *net.UDPConn, want []byte) netip.AddrPort {
	t.Helper()
	if err := receiver.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 65535)
	n, sender, err := receiver.ReadFromUDPAddrPort(data)
	if err != nil || !bytes.Equal(data[:n], want) {
		t.Fatalf("unexpected datagram, received %d bytes, expected %d: %v", n, len(want), err)
	}
	return sender
}

func fixtureUDPNone(t *testing.T, receiver *net.UDPConn) {
	t.Helper()
	if err := receiver.SetReadDeadline(time.Now().Add(125 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var data [65535]byte
	_, _, err := receiver.ReadFromUDPAddrPort(data[:])
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("unexpected UDP receipt or socket state: %v", err)
	}
}

func fixtureUDPRoundTrip(t *testing.T, client, target *net.UDPConn, relay netip.AddrPort, host string, request, response []byte) {
	t.Helper()
	destination := target.LocalAddr().(*net.UDPAddr).AddrPort()
	fixtureUDPWrite(t, client, relay, fixtureUDPFrame(host, destination.Port(), request))
	peer := fixtureUDPRead(t, target, request)
	responseIP := destination.Addr().Unmap()
	if responseIP.IsUnspecified() {
		// localhost can resolve to either family. The dual-stack target
		// replies on the family actually used by the connected target flow.
		if !peer.Addr().Unmap().IsLoopback() {
			t.Fatal("domain fixture received a non-loopback flow")
		}
		responseIP = netip.IPv6Loopback()
		if peer.Addr().Unmap().Is4() {
			responseIP = netip.AddrFrom4([4]byte{127, 0, 0, 1})
		}
	}
	fixtureUDPWrite(t, target, peer, response)
	if sender := fixtureUDPRead(t, client, fixtureUDPFrame(responseIP.String(), destination.Port(), response)); sender != relay {
		t.Fatal("UDP response did not come from the association relay")
	}
}

func requireSOCKSUDPControlClosed(t *testing.T, control *net.TCPConn) {
	t.Helper()
	_ = control.SetReadDeadline(time.Now().Add(3 * time.Second))
	var one [1]byte
	n, err := control.Read(one[:])
	if n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("association control stayed usable: %v", err)
	}
}

func TestManagedSOCKS5UDPProcesses(t *testing.T) {
	binaryPath := os.Getenv("SPLICORE_RUNTIME_BINARY")
	if binaryPath == "" {
		t.Skip("set SPLICORE_RUNTIME_BINARY to the native built core to run process qualification")
	}
	if !filepath.IsAbs(binaryPath) {
		t.Fatal("native binary path must be absolute")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 55*time.Second)
	defer cancel()
	server := newProxyProcessCore(t, binaryPath, requireSocksRedacted)
	local := newProxyProcessCore(t, binaryPath, requireSocksRedacted)
	stopServer, stopLocal := server.start(ctx), local.start(ctx)
	serverPort, localPort := testkit.PeerPort(t, "tcp"), testkit.PeerPort(t, "tcp")
	serverAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort))
	localAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort))
	draft := server.file("socks5-udp.json", fmt.Appendf(nil, `{
		"schema":1,"name":"managed UDP process fixture","listener":{"port":%d},"settings":{"auth":true,"udp":true},
		"users":[{"account_name":"first","username":"alice","password":%q},
		         {"account_name":"second","username":"bob","password":%q}]}`, serverPort, socksAlice, socksBob))
	plan := server.file("socks5-udp.plan", server.cli(ctx, "inbound", "plan", "--protocol", "socks5", "--file", draft))
	var created application.CreationResult
	if err := json.Unmarshal(server.cli(ctx, "inbound", "apply", "--protocol", "socks5", "--file", draft, "--plan", plan), &created); err != nil || len(created.Bindings) != 2 {
		t.Fatal("invalid managed UDP creation result")
	}
	id, aliceID, bobID := created.InboundID, created.Bindings[0].BindingID, created.Bindings[1].BindingID

	t.Run("independent-rfc1928", func(t *testing.T) {
		client := fixtureSOCKSUDP(t, "127.0.0.1")
		control := openSocksFixture(t, serverAddr, "alice", socksAlice, 0)
		defer control.Close()
		relay := fixtureUDPAssociate(t, control, 0)
		for _, row := range []struct{ name, host, target string }{
			{"ipv4", "127.0.0.1", "127.0.0.1"}, {"ipv6", "::1", "::1"}, {"domain", "localhost", ""},
		} {
			t.Run(row.name, func(t *testing.T) {
				target := fixtureSOCKSUDP(t, row.target)
				data := bytes.Repeat([]byte(row.name), 300)
				fixtureUDPRoundTrip(t, client, target, relay, row.host, data, []byte("independent response"))
			})
		}
	})

	t.Run("same-ip-isolation-and-invalid-frames", func(t *testing.T) {
		target := fixtureSOCKSUDP(t, "127.0.0.1")
		port := target.LocalAddr().(*net.UDPAddr).AddrPort().Port()
		alice, bob := fixtureSOCKSUDP(t, "127.0.0.1"), fixtureSOCKSUDP(t, "127.0.0.1")
		a := openSocksFixture(t, serverAddr, "alice", socksAlice, 0)
		b := openSocksFixture(t, serverAddr, "bob", socksBob, 0)
		defer b.Close()
		aRelay := fixtureUDPAssociate(t, a, alice.LocalAddr().(*net.UDPAddr).AddrPort().Port())
		bRelay := fixtureUDPAssociate(t, b, 0)
		if aRelay == bRelay {
			t.Fatal("two concurrent associations on the same IP shared a relay")
		}
		fixtureUDPWrite(t, bob, aRelay, fixtureUDPFrame("127.0.0.1", port, []byte("wrong source port")))
		fixtureUDPWrite(t, alice, aRelay, []byte{0, 0, 0, 4, 1})
		fragment := fixtureUDPFrame("127.0.0.1", port, []byte("fragment must be dropped"))
		fragment[2] = 1
		fixtureUDPWrite(t, alice, aRelay, fragment)
		reserved := fixtureUDPFrame("127.0.0.1", port, []byte("reserved bits must be dropped"))
		reserved[0] = 1
		fixtureUDPWrite(t, alice, aRelay, reserved)
		fixtureUDPNone(t, target)
		t.Run("concurrent-bindings", func(t *testing.T) {
			t.Run("alice", func(t *testing.T) {
				t.Parallel()
				fixtureUDPRoundTrip(t, alice, target, aRelay, "127.0.0.1", []byte("alice"), []byte("reply for alice"))
			})
			t.Run("bob", func(t *testing.T) {
				t.Parallel()
				fixtureUDPRoundTrip(t, bob, fixtureSOCKSUDP(t, "127.0.0.1"), bRelay, "127.0.0.1", []byte("bob"), []byte("reply for bob"))
			})
		})
		fixtureUDPNone(t, alice)
		if err := a.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		requireSOCKSUDPControlClosed(t, a)
		fixtureUDPWrite(t, alice, aRelay, fixtureUDPFrame("127.0.0.1", port, []byte("after control EOF")))
		fixtureUDPNone(t, target)
		moved := fixtureSOCKSUDP(t, "127.0.0.1")
		replacement := openSocksFixture(t, serverAddr, "alice", socksAlice, 0)
		defer replacement.Close()
		replacementRelay := fixtureUDPAssociate(t, replacement, moved.LocalAddr().(*net.UDPAddr).AddrPort().Port())
		fixtureUDPRoundTrip(t, moved, target, replacementRelay, "127.0.0.1", []byte("changed UDP source port"), []byte("new association"))
	})

	t.Run("scoped-direct-and-reject", func(t *testing.T) {
		ruleID, err := identity.NewID()
		if err != nil {
			t.Fatal(err)
		}
		route := func(kind P.ActionKind) {
			server.mutation(ctx, application.ClientMutation{Resource: "network", Action: "replace", Network: &P.Config{
				Route: P.RouteProfile{Rules: []P.RouteRule{{ID: ruleID, Name: "UDP server fixture",
					Match: P.RuleMatch{ServerInbounds: []identity.ID{id}}, Action: P.Action{Kind: kind}}}},
			}})
		}
		route(P.Reject)
		server.cli(ctx, "client", "start")
		target := fixtureSOCKSUDP(t, "127.0.0.1")
		client := fixtureSOCKSUDP(t, "127.0.0.1")
		control := openSocksFixture(t, serverAddr, "alice", socksAlice, 0)
		defer control.Close()
		relay := fixtureUDPAssociate(t, control, 0)
		fixtureUDPWrite(t, client, relay, fixtureUDPFrame("127.0.0.1", target.LocalAddr().(*net.UDPAddr).AddrPort().Port(), []byte("rejected")))
		fixtureUDPNone(t, target)
		route(P.Direct)
		fixtureUDPRoundTrip(t, client, target, relay, "127.0.0.1", []byte("protected direct"), []byte("direct response"))
	})

	t.Run("two-core-tcp-udp-dns-and-restart", func(t *testing.T) {
		data, err := server.command(ctx, "inbound", "export", "--id", string(id), "--binding-id", string(aliceID), "--format", "mihomo", "--client-version", "1.19.32")
		var exported application.ExportResult
		var document struct {
			Proxies []struct {
				UDP bool `json:"udp"`
			} `json:"proxies"`
		}
		if err != nil || json.Unmarshal(data, &exported) != nil || json.Unmarshal([]byte(exported.Content), &document) != nil ||
			len(document.Proxies) != 1 || !document.Proxies[0].UDP {
			t.Fatal("authorized SOCKS5 export did not advertise UDP")
		}
		preview, err := local.control.PreviewManagement(ctx, application.ManagementRequest{
			Operation: "import", InputFormat: "mihomo", Content: exported.Content, GenerateOutbounds: true, Engine: "native",
		})
		if err != nil || !preview.Applicable {
			t.Fatal("exported UDP node did not import")
		}
		if _, err = local.control.ApplyManagement(ctx, application.ManagementApply{Token: preview.Token, Revision: preview.Revision}); err != nil {
			t.Fatal(err)
		}
		status, err := local.control.ClientStatus(ctx)
		if err != nil || len(status.State.Nodes) != 1 {
			t.Fatal("imported node missing")
		}
		node := status.State.Nodes[0]
		options, err := proxy.Decode(node.Options.Data)
		if err != nil || !options.Auth || !options.UDP {
			t.Fatal("imported node lost authentication or UDP")
		}
		var outbound identity.ID
		for _, candidate := range status.State.Outbounds {
			if candidate.NodeID != nil && *candidate.NodeID == node.ID {
				outbound = candidate.ID
			}
		}
		if outbound == "" {
			t.Fatal("imported UDP node did not produce an outbound")
		}
		if exported, err := local.control.ExportNodes(ctx, application.NodeExportRequest{IDs: []identity.ID{node.ID}, Format: "mihomo", ClientVersion: "1.19.32", RevealSecrets: true}); err != nil ||
			json.Unmarshal([]byte(exported.Content), &document) != nil || len(document.Proxies) != 1 || !document.Proxies[0].UDP {
			t.Fatal("node export lost UDP capability")
		}
		local.mutation(ctx, application.ClientMutation{Resource: "local-inbound", Action: "create",
			LocalInbound: &client.LocalInbound{Name: "UDP application fixture", Kind: "socks5", SelectedOutbound: outbound,
				Listen: access.Endpoint{Host: "127.0.0.1", Port: uint16(localPort)}}})
		local.cli(ctx, "client", "start")
		tcpTarget := socksHalfCloseTarget(t, "127.0.0.1")
		tcp := openSocksFixture(t, localAddr, "", "", 0)
		socksFixtureConnect(t, tcp, "127.0.0.1", tcpTarget, 0)
		socksFixtureTransfer(t, tcp, []byte("TCP remains available with UDP enabled"))
		through := func() *net.TCPConn {
			control := openSocksFixture(t, localAddr, "", "", 0)
			client := fixtureSOCKSUDP(t, "127.0.0.1")
			relay := fixtureUDPAssociate(t, control, 0)
			v4, v6 := fixtureSOCKSUDP(t, "127.0.0.1"), fixtureSOCKSUDP(t, "::1")
			fixtureUDPRoundTrip(t, client, v4, relay, "127.0.0.1", []byte("two-Core UDP"), []byte("v4"))
			fixtureUDPRoundTrip(t, client, v6, relay, "::1", bytes.Repeat([]byte("v6"), 1024), []byte("v6"))
			dnsTarget := fixtureSOCKSUDP(t, "")
			query := new(dns.Msg)
			query.SetQuestion("udp.fixture.invalid.", dns.TypeA)
			response := new(dns.Msg)
			response.SetReply(query)
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 65)}}
			wireQuery, queryErr := query.Pack()
			wireAnswer, answerErr := response.Pack()
			if queryErr != nil || answerErr != nil {
				t.Fatalf("DNS fixture packing failed: %v / %v", queryErr, answerErr)
			}
			fixtureUDPRoundTrip(t, client, dnsTarget, relay, "localhost", wireQuery, wireAnswer)
			return control
		}
		active := through()
		in, _ := server.view(ctx, id)
		for _, b := range in.Bindings {
			if b.BindingID == aliceID && (b.Stats.UDPSessions < 3 || b.Stats.Upload < 2048 || b.Stats.Download == 0) ||
				b.BindingID == bobID && (b.Stats.UDPSessions != 1 || b.Stats.Upload != 3 || b.Stats.Download != 13) {
				t.Fatal("managed UDP payload was not correctly attributed to its binding")
			}
		}
		stopLocal()
		requireSOCKSUDPControlClosed(t, active)
		stopServer()
		stopServer, stopLocal = server.start(ctx), local.start(ctx)
		_ = through().Close()
	})

	t.Run("credential-revocation-and-stop", func(t *testing.T) {
		control := openSocksFixture(t, serverAddr, "bob", socksBob, 0)
		client := fixtureSOCKSUDP(t, "127.0.0.1")
		target := fixtureSOCKSUDP(t, "127.0.0.1")
		relay := fixtureUDPAssociate(t, control, 0)
		fixtureUDPRoundTrip(t, client, target, relay, "127.0.0.1", []byte("before revoke"), []byte("answer"))
		in, revision := server.view(ctx, id)
		var bindingRevision identity.Revision
		for _, b := range in.Bindings {
			if b.BindingID == bobID {
				bindingRevision = b.Revision
			}
		}
		server.mutateInbound(ctx, "binding", id, application.BindingRequest{
			Action: "rotate", Enabled: true, BindingID: bobID, Revision: revision, ResourceRevision: bindingRevision,
			Credential: &application.CredentialInput{Kind: access.UsernamePassword,
				Value: fmt.Sprintf(`{"username":"bob","password":%q}`, socksRotated)},
		})
		requireSOCKSUDPControlClosed(t, control)
		_ = openSocksFixture(t, serverAddr, "bob", socksBob, 1).Close()
		control = openSocksFixture(t, serverAddr, "bob", socksRotated, 0)
		relay = fixtureUDPAssociate(t, control, 0)
		fixtureUDPRoundTrip(t, client, target, relay, "127.0.0.1", []byte("after rotation"), []byte("answer"))
		in, revision = server.view(ctx, id)
		server.mutateInbound(ctx, "lifecycle", id, application.SOCKS5LifecycleRequest{Action: "stop", Revision: revision, ResourceRevision: in.Inbound.Revision})
		requireSOCKSUDPControlClosed(t, control)
	})
	stopLocal()
	stopServer()
	for _, core := range []*proxyProcessCore{local, server} {
		data, err := os.ReadFile(filepath.Join(core.root, "state", "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		requireSocksRedacted(t, data)
	}
}
