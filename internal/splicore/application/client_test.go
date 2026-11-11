package application_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/api"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/native"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/snell"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/storage/sqlite"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func enableClient(t *testing.T, s *application.Service) {
	t.Helper()
	r, err := registry.NewOutbounds(native.SnellOutboundFactory{})
	if err == nil {
		err = s.EnableClientRuntime(context.Background(), r)
	}
	if err != nil {
		t.Fatal(err)
	}
}
func clientApply(t *testing.T, s *application.Service, m application.ClientMutation) application.ClientResult {
	t.Helper()
	b, _ := json.Marshal(m)
	p, err := s.PlanClient(context.Background(), b)
	if err != nil {
		t.Fatal("plan", err)
	}
	result, err := s.ApplyClient(context.Background(), application.ApplyRequest{Document: b, Digest: p.Digest, Revision: p.Revision})
	if err != nil {
		t.Fatal("apply", err)
	}
	return result
}
func echoTarget(t *testing.T, host string) access.Endpoint {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = l.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(30 * time.Second))
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return access.Endpoint{Host: host, Port: uint16(l.Addr().(*net.TCPAddr).Port)}
}
func socksConn(port uint16, target access.Endpoint) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	_, err = socks.Handshake(c, socks.Connect, access.Endpoint{Host: target.Host, Port: target.Port})
	if err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}
func transfer(port uint16, target access.Endpoint, payload []byte) error {
	c, err := socksConn(port, target)
	if err != nil {
		return err
	}
	defer c.Close()
	done := make(chan error, 1)
	go func() {
		_, e := c.Write(payload)
		done <- e
	}()
	// Snell command-1 EOF closes its tunnel by the frozen upstream contract.
	// Check the entire framed payload before ending the application session.
	received := make([]byte, len(payload))
	_, err = io.ReadFull(c, received)
	writeErr := <-done
	if err != nil {
		return err
	}
	if writeErr != nil {
		return writeErr
	}
	if len(received) != len(payload) || sha256.Sum256(received) != sha256.Sum256(payload) {
		return fmt.Errorf("integrity mismatch: %d != %d", len(received), len(payload))
	}
	return nil
}
func waitIdle(t *testing.T, s *application.Service) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.WaitClientIdle(ctx); err != nil {
		status, _ := s.ClientStatus(context.Background())
		t.Logf("pending client sessions: %+v", status.Sessions)
		t.Fatal("session cleanup", err)
	}
}
func addNode(t *testing.T, s *application.Service, endpoint access.Endpoint, version int, psk string) identity.ID {
	t.Helper()
	r := clientApply(t, s, application.ClientMutation{Resource: "node", Action: "create", Node: &client.RemoteNode{Name: "synthetic-node", Protocol: snell.Key(version), Endpoint: endpoint, Transport: client.Transport{Kind: "tcp"}, Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: json.RawMessage(fmt.Sprintf(`{"version":%d}`, version))}, Metadata: identity.Metadata{}}, Credential: &application.CredentialInput{Kind: access.PSK, Value: psk}})
	return r.ID
}
func addProxy(t *testing.T, s *application.Service, node identity.ID) identity.ID {
	t.Helper()
	r := clientApply(t, s, application.ClientMutation{Resource: "outbound", Action: "create", Outbound: &client.Outbound{Name: "synthetic-proxy", Kind: "proxy", NodeID: &node, Engine: "native"}})
	return r.ID
}
func addLocal(t *testing.T, s *application.Service, port uint16, selected identity.ID) identity.ID {
	t.Helper()
	r := clientApply(t, s, application.ClientMutation{Resource: "local-inbound", Action: "create", LocalInbound: &client.LocalInbound{Name: "local", Listen: access.Endpoint{Port: port}, SelectedOutbound: selected}})
	return r.ID
}
func remotePSK(t *testing.T, store *sqlite.Store, inbound identity.ID) string {
	t.Helper()
	b, err := store.Binding(context.Background(), inbound)
	if err != nil {
		t.Fatal(err)
	}
	c, err := store.RevealCredential(context.Background(), b.CredentialID)
	if err != nil {
		t.Fatal(err)
	}
	return c.Payload.(access.PSKPayload).Key.Reveal()
}

func TestClientDIRECTAddressesLifecycleAndStats(t *testing.T) {
	ctx := context.Background()
	s, store := setupSnell(t, filepath.Join(t.TempDir(), "direct", "state.db"), nil)
	defer stop(t, s, store)
	enableClient(t, s)
	target := echoTarget(t, "127.0.0.1")
	port := freePort(t)
	inbound := addLocal(t, s, port, "")
	for _, host := range []string{"127.0.0.1", "localhost"} {
		target.Host = host
		if err := transfer(port, target, bytes.Repeat([]byte("DIRECT-payload"), 4096)); err != nil {
			t.Fatal(host, err)
		}
	}
	ipv6 := echoTarget(t, "::1")
	if err := transfer(port, ipv6, []byte("IPv6")); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, s)
	status, err := s.ClientStatus(ctx)
	if err != nil || status.Outbounds[0].Stats.Active != 0 || status.Outbounds[0].Stats.Sessions != 3 || status.LocalStats[0].Stats != status.Outbounds[0].Stats {
		t.Fatal("stats", status, err)
	}
	if !status.Outbounds[0].Available || !status.LocalSOCKSTCP || status.LocalSOCKSUDP != "supported" {
		t.Fatal("capabilities/health", status)
	}
	c, err := socksConn(port, target)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	waitIdle(t, s)
	clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "stop"})
	assertReleased(t, port)
	clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "start"})
	if err := transfer(port, target, []byte("restarted")); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, s)
	clientApply(t, s, application.ClientMutation{Resource: "local-inbound", Action: "delete", ID: inbound})
	assertReleased(t, port)
}

func TestClientSnellVerticalSliceStressRecoveryCoexistence(t *testing.T) {
	for _, version := range []int{5, 6} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			a, as := setupSnell(t, filepath.Join(dir, "a", "state.db"), nil)
			defer func() { stop(t, a, as) }()
			remotePort := freePort(t)
			ar := apply(t, a, doc(remotePort, version))
			psk := remotePSK(t, as, ar.InboundID)
			bpath := filepath.Join(dir, "b", "state.db")
			b, bs := setupSnell(t, bpath, nil)
			defer func() { stop(t, b, bs) }()
			enableClient(t, b)
			serverPort := freePort(t)
			br := apply(t, b, doc(serverPort, 5))
			serverPSK := remotePSK(t, bs, br.InboundID)
			node := addNode(t, b, access.Endpoint{Host: "localhost", Port: remotePort}, version, psk)
			outbound := addProxy(t, b, node)
			clientApply(t, b, application.ClientMutation{Resource: "route", Action: "update", Route: &client.Route{DefaultOutbound: outbound}})
			localPort := freePort(t)
			addLocal(t, b, localPort, "")
			directPort := freePort(t)
			addLocal(t, b, directPort, client.Direct)
			target := echoTarget(t, "127.0.0.1")
			payload := bytes.Repeat([]byte("0123456789abcdef"), 4*1024*1024/16)
			if err := transfer(localPort, target, payload); err != nil {
				t.Fatal("4 MiB", err)
			}
			t.Logf("4 MiB SHA256 %x", sha256.Sum256(payload))
			for _, host := range []string{"127.0.0.1", "localhost"} {
				dest := target
				dest.Host = host
				if err := transfer(localPort, dest, []byte("domain-and-IP")); err != nil {
					t.Fatal(host, err)
				}
			}
			ipv6 := echoTarget(t, "::1")
			if err := transfer(localPort, ipv6, []byte("remote IPv6")); err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			failures := make(chan error, 17)
			for i := range 16 {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					failures <- transfer(localPort, target, bytes.Repeat([]byte{byte(i)}, 64*1024))
				}(i)
			}
			// Splicore B's server simultaneously carries its own traffic.
			peer, peerStore := setupSnell(t, filepath.Join(dir, "peer", "state.db"), nil)
			defer stop(t, peer, peerStore)
			enableClient(t, peer)
			peerNode := addNode(t, peer, access.Endpoint{Host: "127.0.0.1", Port: serverPort}, 5, serverPSK)
			peerOutbound := addProxy(t, peer, peerNode)
			peerPort := freePort(t)
			addLocal(t, peer, peerPort, peerOutbound)
			wg.Add(1)
			go func() {
				defer wg.Done()
				failures <- transfer(peerPort, target, bytes.Repeat([]byte("server-coexistence"), 4096))
			}()
			wg.Wait()
			close(failures)
			for err := range failures {
				if err != nil {
					t.Fatal("concurrent coexistence", err)
				}
			}
			waitIdle(t, b)
			status, err := b.ClientStatus(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, o := range status.Outbounds {
				if o.ID == outbound && (o.Stats.Active != 0 || o.Stats.Sessions != 20 || o.Stats.Upload != o.Stats.Download || !o.Available) {
					t.Fatal("payload observation", o)
				}
			}
			// A session keeps its generation alive during route replacement and credential rotation.
			held, err := socksConn(localPort, target)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = held.Write([]byte("before")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 6)
			if _, err = io.ReadFull(held, buf); err != nil {
				t.Fatal(err)
			}
			clientApply(t, b, application.ClientMutation{Resource: "route", Action: "update", Route: &client.Route{DefaultOutbound: client.Direct}})
			clientApply(t, b, application.ClientMutation{Resource: "node", Action: "rotate", ID: node, Credential: &application.CredentialInput{Kind: access.PSK, Value: psk}})
			if _, err = held.Write([]byte("after")); err != nil {
				t.Fatal(err)
			}
			if _, err = io.ReadFull(held, buf[:5]); err != nil || string(buf[:5]) != "after" {
				t.Fatal("retired generation prematurely closed", err)
			}
			held.Close()
			waitIdle(t, b)
			clientApply(t, b, application.ClientMutation{Resource: "route", Action: "update", Route: &client.Route{DefaultOutbound: outbound}})
			// Abrupt remote close plus refusal must preserve local acceptance, DIRECT, API and B server.
			held, err = socksConn(localPort, target)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = held.Write([]byte("open"))
			if _, err = io.ReadFull(held, buf[:4]); err != nil {
				t.Fatal(err)
			}
			if err = a.CloseRuntime(ctx); err != nil {
				t.Fatal(err)
			}
			_, _ = held.Read(buf)
			held.Close()
			waitIdle(t, b)
			if err = transfer(localPort, target, []byte("refused")); err == nil {
				t.Fatal("offline remote accepted traffic")
			}
			waitIdle(t, b)
			if err = transfer(directPort, target, []byte("DIRECT remains")); err != nil {
				t.Fatal(err)
			}
			if err = transfer(peerPort, target, []byte("B server remains")); err != nil {
				t.Fatal(err)
			}
			system, err := b.System(ctx)
			if err != nil || len(system.ServerRuntimes) != 1 || system.ClientRuntime == nil {
				t.Fatal("single daemon status", err)
			}
			as.Close()
			a, as = setupSnell(t, filepath.Join(dir, "a", "state.db"), nil)
			if err = transfer(localPort, target, []byte("reconnected")); err != nil {
				t.Fatal("remote reconnect", err)
			}
			waitIdle(t, b)
			if err = b.CloseRuntime(ctx); err != nil {
				t.Fatal(err)
			}
			bs.Close()
			assertReleased(t, localPort)
			assertReleased(t, serverPort)
			b, bs = setupSnell(t, bpath, nil)
			enableClient(t, b)
			if err = transfer(localPort, target, []byte("SQLite restored")); err != nil {
				t.Fatal("client recovery", err)
			}
			if err = transfer(peerPort, target, []byte("server restored")); err != nil {
				t.Fatal("server recovery", err)
			}
			waitIdle(t, b)
		})
	}
}

func TestClientNegativeTransactionsReferencesRotationAPI(t *testing.T) {
	ctx := context.Background()
	s, store := setupSnell(t, filepath.Join(t.TempDir(), "state", "state.db"), nil)
	defer stop(t, s, store)
	enableClient(t, s)
	node := addNode(t, s, access.Endpoint{Host: "example.test", Port: 12345}, 5, "SyntheticClientPSK123456")
	outbound := addProxy(t, s, node)
	status, _ := s.ClientStatus(ctx)
	n := status.State.Nodes[0]
	n.Name = "renamed"
	clientApply(t, s, application.ClientMutation{Resource: "node", Action: "update", ID: node, Node: &n})
	for _, m := range []application.ClientMutation{
		{Resource: "node", Action: "delete", ID: node},
		{Resource: "node", Action: "rotate", ID: node, Credential: &application.CredentialInput{Kind: access.PSK, Value: ""}},
		{Resource: "node", Action: "rotate", ID: node, Credential: &application.CredentialInput{Kind: access.PSK, Value: "short"}},
		{Resource: "outbound", Action: "create", Outbound: &client.Outbound{Name: "bad", Kind: "proxy", Engine: "native"}},
		{Resource: "outbound", Action: "create", Outbound: &client.Outbound{Name: "bad", Kind: "proxy", NodeID: &node, Engine: "xray"}},
		{Resource: "route", Action: "update", Route: &client.Route{DefaultOutbound: identity.ID("missing")}},
		{Resource: "local-inbound", Action: "create", LocalInbound: &client.LocalInbound{Name: "bad", Listen: access.Endpoint{Host: "0.0.0.0", Port: 23456}}},
	} {
		b, _ := json.Marshal(m)
		if _, err := s.PlanClient(ctx, b); err == nil {
			t.Fatal("negative accepted", m)
		}
	}
	for _, change := range []func(*client.RemoteNode){func(n *client.RemoteNode) { n.ID = "invalid" }, func(n *client.RemoteNode) { n.Endpoint.Host = "" }, func(n *client.RemoteNode) { n.Endpoint.Port = 0 }, func(n *client.RemoteNode) { n.Protocol = snell.Key(7); n.Options.Data = []byte(`{"version":7}`) }, func(n *client.RemoteNode) { n.CredentialID = "" }} {
		bad := n
		change(&bad)
		b, _ := json.Marshal(application.ClientMutation{Resource: "node", Action: "update", ID: node, Node: &bad})
		if _, err := s.PlanClient(ctx, b); err == nil {
			t.Fatal("invalid node accepted")
		}
	}
	// Bind failure leaves committed state and the old listener alive.
	goodPort := freePort(t)
	addLocal(t, s, goodPort, client.Direct)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	before, _ := s.ClientStatus(ctx)
	m := application.ClientMutation{Resource: "local-inbound", Action: "create", LocalInbound: &client.LocalInbound{Name: "conflict", Listen: access.Endpoint{Port: uint16(occupied.Addr().(*net.TCPAddr).Port)}}}
	raw, _ := json.Marshal(m)
	plan, err := s.PlanClient(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.ApplyClient(ctx, application.ApplyRequest{Document: raw, Digest: plan.Digest, Revision: plan.Revision})
	var de *identity.Error
	if !errors.As(err, &de) || de.Code != identity.PortConflict {
		t.Fatal("port conflict", err)
	}
	after, _ := s.ClientStatus(ctx)
	if before.State.Revision != after.State.Revision || len(after.State.LocalInbounds) != 1 {
		t.Fatal("failed transaction published")
	}
	target := echoTarget(t, "127.0.0.1")
	if err = transfer(goodPort, target, []byte("rollback")); err != nil {
		t.Fatal(err)
	}
	h := httptest.NewServer(api.Handler(s))
	defer h.Close()
	ctl := transport.TestClient(h.Client(), h.URL)
	defer ctl.Close()
	b, _ := io.ReadAll(mustGet(t, h.URL+"/api/v1/nodes"))
	if strings.Contains(string(b), "SyntheticClientPSK123456") {
		t.Fatal("API secret leak")
	}
	st, err := ctl.ClientStatus(ctx)
	if err != nil || st.State.Nodes[0].Name != "renamed" {
		t.Fatal("typed client status", err)
	}
	o := st.State.Outbounds[0]
	for _, v := range st.State.Outbounds {
		if v.ID == outbound {
			o = v
		}
	}
	o.Name = "renamed-outbound"
	clientApply(t, s, application.ClientMutation{Resource: "outbound", Action: "update", ID: outbound, Outbound: &o})
	clientApply(t, s, application.ClientMutation{Resource: "outbound", Action: "delete", ID: outbound})
	clientApply(t, s, application.ClientMutation{Resource: "node", Action: "delete", ID: node})
	final, _ := s.ClientStatus(ctx)
	if len(final.State.Nodes) != 0 {
		t.Fatal("node delete")
	}
}
func mustGet(t *testing.T, url string) io.ReadCloser {
	t.Helper()
	r, e := http.Get(url)
	if e != nil {
		t.Fatal(e)
	}
	if r.StatusCode != 200 {
		t.Fatal(r.Status)
	}
	t.Cleanup(func() { r.Body.Close() })
	return r.Body
}
