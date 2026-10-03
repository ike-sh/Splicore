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
	mm "github.com/sagernet/sing-box/internal/splicore/protocol/mieru"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func expansionFree(t *testing.T, network, host string) uint16 {
	t.Helper()
	if network == "udp" {
		pc, err := net.ListenPacket(network, net.JoinHostPort(host, "0"))
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		return uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	}
	l, err := net.Listen(network, net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

func TestPhase11MieruUDPUnderlay(t *testing.T) {
	cases := expansionCases(t)
	c := cases[len(cases)-1]
	c.transport = "udp"
	c.settings = mm.Settings{Transport: "udp", MTU: 1500, Multiplex: "default"}
	c.options = []byte(`{"transport":"udp"}`)
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, phase8Protocols)
	defer stop(t, s, store)
	r, _ := registry.NewOutbounds(c.factory)
	if err := s.EnableClientRuntime(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	remote := expansionFree(t, "udp", "127.0.0.1")
	created := expansionCreation(t, s, c, "127.0.0.1", remote)
	node := expansionNode(t, s, c, access.Endpoint{Host: "127.0.0.1", Port: remote}, expansionCredential(t, store, created, 0))
	out := expansionProxy(t, s, node, "native")
	local := freePort(t)
	addLocal(t, s, local, out)
	tcp := echoTarget(t, "127.0.0.1")
	udp := expansionUDP(t, "::1")
	if err := transfer(local, tcp, bytes.Repeat([]byte("0123456789abcdef"), 4*1024*1024/16)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	fail := make(chan error, 32)
	for range 16 {
		wg.Add(2)
		go func() { defer wg.Done(); fail <- expansionBoundedTCP(local, tcp, []byte("Mieru-UDP-underlay-TCP")) }()
		go func() { defer wg.Done(); fail <- expansionUDPTraffic(local, udp, []byte("Mieru-UDP-underlay-UDP")) }()
	}
	wg.Wait()
	close(fail)
	for err := range fail {
		if err != nil {
			t.Fatal(err)
		}
	}
	waitIdle(t, s)
}

func TestPhase11MieruUDPServerEndpointFamilies(t *testing.T) {
	cases := expansionCases(t)
	c := cases[len(cases)-1]
	c.transport = "udp"
	c.settings = mm.Settings{Transport: "udp", MTU: 1500, Multiplex: "default"}
	c.options = []byte(`{"transport":"udp"}`)
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, phase8Protocols)
	defer stop(t, s, store)
	r, _ := registry.NewOutbounds(c.factory)
	if err := s.EnableClientRuntime(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"::1", "localhost"} {
		t.Run(host, func(t *testing.T) {
			listen := host
			if host == "localhost" {
				ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip", host)
				if err != nil || len(ips) == 0 {
					t.Fatal(err)
				}
				if !ips[0].IsLoopback() {
					t.Fatal("fixture resolver escaped loopback")
				}
				listen = ips[0].String()
			}
			port := expansionFree(t, "udp", listen)
			created := expansionCreation(t, s, c, listen, port)
			node := expansionNode(t, s, c, access.Endpoint{Host: host, Port: port}, expansionCredential(t, store, created, 0))
			out := expansionProxy(t, s, node, "native")
			local := freePort(t)
			addLocal(t, s, local, out)
			if err := expansionBoundedTCP(local, echoTarget(t, "127.0.0.1"), []byte("UDP-underlay-endpoint")); err != nil {
				t.Fatal(err)
			}
			if err := expansionUDPTraffic(local, expansionUDP(t, "127.0.0.1"), []byte("UDP-underlay-endpoint")); err != nil {
				t.Fatal(err)
			}
			waitIdle(t, s)
		})
	}
}
func expansionBoundedTCP(port uint16, target access.Endpoint, payload []byte) error {
	c, err := socksConn(port, target)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err = c.Write(payload); err != nil {
		return err
	}
	b := make([]byte, len(payload))
	if _, err = io.ReadFull(c, b); err != nil {
		return err
	}
	if string(b) != string(payload) {
		return fmt.Errorf("integrity mismatch")
	}
	return nil
}
func wrongInput(p access.Payload) application.CredentialInput {
	input := payloadInput(p)
	switch p.Kind() {
	case access.PSK, access.Password:
		input.Value = "SyntheticWrongPasswordPhase11"
	case access.UUID:
		id, _ := identity.NewID()
		input.Value = string(id)
	case access.UUIDPassword, access.UsernamePassword:
		var value map[string]string
		_ = json.Unmarshal([]byte(input.Value), &value)
		value["password"] = "SyntheticWrongPasswordPhase11"
		b, _ := json.Marshal(value)
		input.Value = string(b)
	}
	return input
}
func TestPhase11NativeEndpointsWrongAuthAndReconnect(t *testing.T) {
	for _, c := range expansionCases(t) {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "remote", "state.db")
			remote, rs := setupProtocols(t, path, nil, phase8Protocols)
			defer func() { stop(t, remote, rs) }()
			local, ls := setupProtocols(t, filepath.Join(t.TempDir(), "local", "state.db"), nil, phase8Protocols)
			defer stop(t, local, ls)
			r, _ := registry.NewOutbounds(c.factory)
			if err := local.EnableClientRuntime(context.Background(), r); err != nil {
				t.Fatal(err)
			}
			network := "tcp"
			if c.transport == "quic" {
				network = "udp"
			}
			port := expansionFree(t, network, "::1")
			created := expansionCreation(t, remote, c, "::1", port)
			cred := expansionCredential(t, rs, created, 0)
			node := expansionNode(t, local, c, access.Endpoint{Host: "::1", Port: port}, cred)
			outbound := expansionProxy(t, local, node, "native")
			socksPort := freePort(t)
			addLocal(t, local, socksPort, outbound)
			tcp := echoTarget(t, "127.0.0.1")
			udp := expansionUDP(t, "::1")
			if err := expansionBoundedTCP(socksPort, tcp, []byte("IPv6-server-endpoint")); err != nil {
				t.Fatal(err)
			}
			if err := expansionUDPTraffic(socksPort, udp, []byte("IPv6-server-endpoint")); err != nil {
				t.Fatal(err)
			}
			// Move to a literal IPv4 endpoint; the main matrix independently proves a
			// domain server endpoint. Reconcile rebuilds only this outbound lease.
			ipv4 := expansionFree(t, network, "127.0.0.1")
			other := expansionCreation(t, remote, c, "127.0.0.1", ipv4)
			status, _ := local.ClientStatus(context.Background())
			n := status.State.Nodes[0]
			n.Endpoint = access.Endpoint{Host: "127.0.0.1", Port: ipv4}
			clientApply(t, local, application.ClientMutation{Resource: "node", Action: "update", ID: node, Node: &n})
			input := payloadInput(expansionCredential(t, rs, other, 0))
			clientApply(t, local, application.ClientMutation{Resource: "node", Action: "rotate", ID: node, Credential: &input})
			if err := expansionBoundedTCP(socksPort, tcp, []byte("IPv4-server-endpoint")); err != nil {
				t.Fatal(err)
			}
			// Well-formed wrong authentication is intent, observed passively by traffic.
			bad := wrongInput(expansionCredential(t, rs, other, 0))
			clientApply(t, local, application.ClientMutation{Resource: "node", Action: "rotate", ID: node, Credential: &bad})
			if err := expansionBoundedTCP(socksPort, tcp, []byte("must-reject")); err == nil {
				t.Fatal("wrong authentication forwarded TCP")
			}
			if err := expansionUDPTraffic(socksPort, udp, []byte("must-reject")); err == nil {
				t.Fatal("wrong authentication forwarded UDP")
			}
			clientApply(t, local, application.ClientMutation{Resource: "node", Action: "rotate", ID: node, Credential: &input})
			if err := expansionBoundedTCP(socksPort, tcp, []byte("valid-after-wrong")); err != nil {
				t.Fatal(err)
			}
			held, err := socksConn(socksPort, tcp)
			if err != nil {
				t.Fatal(err)
			}
			_ = held.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = held.Write([]byte("open"))
			if _, err = io.ReadFull(held, make([]byte, 4)); err != nil {
				t.Fatal(err)
			}
			if err = remote.CloseRuntime(context.Background()); err != nil {
				t.Fatal(err)
			}
			_ = rs.Close()
			_, _ = held.Read(make([]byte, 1))
			_ = held.Close()
			waitIdle(t, local)
			if err = expansionBoundedTCP(socksPort, tcp, []byte("offline")); err == nil {
				t.Fatal("offline remote forwarded traffic")
			}
			direct := freePort(t)
			addLocal(t, local, direct, client.Direct)
			if err = expansionBoundedTCP(direct, tcp, []byte("DIRECT-isolated")); err != nil {
				t.Fatal(err)
			}
			waitIdle(t, local)
			health, _ := local.ClientStatus(context.Background())
			for _, o := range health.Outbounds {
				if o.ID == outbound && (o.Available || o.LastError == "") {
					t.Fatal("offline passive health absent")
				}
			}
			remote, rs = setupProtocols(t, path, nil, phase8Protocols)
			if err = expansionBoundedTCP(socksPort, tcp, []byte("remote-reconnected")); err != nil {
				t.Fatal(err)
			}
			if err = expansionUDPTraffic(socksPort, udp, []byte("remote-reconnected")); err != nil {
				t.Fatal(err)
			}
			waitIdle(t, local)
		})
	}
}

func TestPhase11MieruClientLifecycle(t *testing.T) {
	cases := expansionCases(t)
	c := cases[len(cases)-1]
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, phase8Protocols)
	defer stop(t, s, store)
	r, _ := registry.NewOutbounds(native.MieruOutboundFactory{})
	if err := s.EnableClientRuntime(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	nodes := []identity.ID{}
	ports := []uint16{}
	outbounds := []identity.ID{}
	locals := []identity.ID{}
	for account := range 2 {
		remote := freePort(t)
		created := expansionCreation(t, s, c, "127.0.0.1", remote)
		node := expansionNode(t, s, c, access.Endpoint{Host: "127.0.0.1", Port: remote}, expansionCredential(t, store, created, account))
		nodes = append(nodes, node)
		out := expansionProxy(t, s, node, "native")
		outbounds = append(outbounds, out)
		port := freePort(t)
		ports = append(ports, port)
		locals = append(locals, addLocal(t, s, port, out))
	}
	tcp := echoTarget(t, "127.0.0.1")
	udp := expansionUDP(t, "127.0.0.1")
	for _, port := range ports {
		if err := expansionBoundedTCP(port, tcp, []byte("isolated-client")); err != nil {
			t.Fatal(err)
		}
		if err := expansionUDPTraffic(port, udp, []byte("isolated-client")); err != nil {
			t.Fatal(err)
		}
	}
	waitIdle(t, s)
	clientApply(t, s, application.ClientMutation{Resource: "local-inbound", Action: "delete", ID: locals[0]})
	clientApply(t, s, application.ClientMutation{Resource: "outbound", Action: "delete", ID: outbounds[0]})
	clientApply(t, s, application.ClientMutation{Resource: "node", Action: "delete", ID: nodes[0]})
	if err := expansionBoundedTCP(ports[1], tcp, []byte("sibling-survives")); err != nil {
		t.Fatal(err)
	}
	if err := expansionUDPTraffic(ports[1], udp, []byte("sibling-survives")); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, s)
}
