package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/engine/native"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

type failedClientFactory struct{ native.SnellOutboundFactory }

func (failedClientFactory) Build(context.Context, client.RemoteNode, access.Credential) (ports.ClientDialer, error) {
	return nil, identity.Err(identity.Unavailable, "synthetic startup failure")
}
func TestClientStartupFailureCompensatesAndPreservesServer(t *testing.T) {
	s, store := setupSnell(t, filepath.Join(t.TempDir(), "state", "state.db"), nil)
	defer stop(t, s, store)
	port := freePort(t)
	ar := apply(t, s, doc(port, 5))
	factories, _ := registry.NewOutbounds(failedClientFactory{})
	if err := s.EnableClientRuntime(context.Background(), factories); err != nil {
		t.Fatal(err)
	}
	localPort := freePort(t)
	addLocal(t, s, localPort, client.Direct)
	node := addNode(t, s, access.Endpoint{Host: "127.0.0.1", Port: port}, 5, remotePSK(t, store, ar.InboundID))
	before, _ := s.ClientStatus(context.Background())
	b, _ := json.Marshal(application.ClientMutation{Resource: "outbound", Action: "create", Outbound: &client.Outbound{Name: "failed", Kind: "proxy", NodeID: &node, Engine: "native"}})
	p, err := s.PlanClient(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.ApplyClient(context.Background(), application.ApplyRequest{Document: b, Digest: p.Digest, Revision: p.Revision})
	if err == nil {
		t.Fatal("start failure committed")
	}
	after, _ := s.ClientStatus(context.Background())
	if after.State.Revision != before.State.Revision || len(after.State.Outbounds) != 1 {
		t.Fatal("candidate leaked")
	}
	state, _ := store.State(context.Background())
	if state.PendingTransactions != 0 {
		t.Fatal("pending operation leaked")
	}
	target := echoTarget(t, "127.0.0.1")
	if err = transfer(localPort, target, []byte("DIRECT after failure")); err != nil {
		t.Fatal(err)
	}
	peer, ps := setupSnell(t, filepath.Join(t.TempDir(), "peer", "state.db"), nil)
	defer stop(t, peer, ps)
	enableClient(t, peer)
	nid := addNode(t, peer, access.Endpoint{Host: "127.0.0.1", Port: port}, 5, remotePSK(t, store, ar.InboundID))
	oid := addProxy(t, peer, nid)
	pp := freePort(t)
	addLocal(t, peer, pp, oid)
	if err = transfer(pp, target, []byte("server after failure")); err != nil {
		t.Fatal(err)
	}
}
func TestClientRecoveryPortConflictPreservesServerAndAPI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "state.db")
	s, store := setupSnell(t, path, nil)
	enableClient(t, s)
	serverPort := freePort(t)
	ar := apply(t, s, doc(serverPort, 5))
	psk := remotePSK(t, store, ar.InboundID)
	localPort := freePort(t)
	lid := addLocal(t, s, localPort, client.Direct)
	stop(t, s, store)
	occupied, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", portText(localPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	s, store = setupSnell(t, path, nil)
	defer stop(t, s, store)
	enableClient(t, s)
	status, err := s.ClientStatus(context.Background())
	if err != nil || status.Health != "degraded" || status.LastError != "client_recovery_failed" {
		t.Fatal("recovery isolation", status, err)
	}
	system, err := s.System(context.Background())
	if err != nil || len(system.ServerRuntimes) != 1 || system.ServerRuntimes[0].Health != "healthy" {
		t.Fatal("server recovery affected", err)
	}
	peer, ps := setupSnell(t, filepath.Join(t.TempDir(), "peer", "state.db"), nil)
	defer stop(t, peer, ps)
	enableClient(t, peer)
	nid := addNode(t, peer, access.Endpoint{Host: "127.0.0.1", Port: serverPort}, 5, psk)
	oid := addProxy(t, peer, nid)
	pp := freePort(t)
	addLocal(t, peer, pp, oid)
	target := echoTarget(t, "127.0.0.1")
	if err = transfer(pp, target, []byte("server while client degraded")); err != nil {
		t.Fatal(err)
	}
	occupied.Close()
	clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "start"})
	if err = transfer(localPort, target, []byte("recovery reconciled")); err != nil {
		t.Fatal(err)
	}
	clientApply(t, s, application.ClientMutation{Resource: "local-inbound", Action: "delete", ID: lid})
}
func TestSnellOutboundRemoteUDPIsSeparateFromLocalSOCKSUDP(t *testing.T) {
	for _, version := range []int{5, 6} {
		t.Run(portText(uint16(version)), func(t *testing.T) {
			ctx := context.Background()
			s, store := setupSnell(t, filepath.Join(t.TempDir(), "state", "state.db"), nil)
			defer stop(t, s, store)
			enableClient(t, s)
			port := freePort(t)
			r := apply(t, s, doc(port, version))
			nodeID := addNode(t, s, access.Endpoint{Host: "127.0.0.1", Port: port}, version, remotePSK(t, store, r.InboundID))
			state, _ := store.ClientState(ctx)
			n := state.Nodes[0]
			c, err := store.RevealCredential(ctx, n.CredentialID)
			if err != nil {
				t.Fatal(err)
			}
			if c.OwnerNodeID == nil || *c.OwnerNodeID != nodeID {
				t.Fatal("owner")
			}
			d, err := (native.SnellOutboundFactory{}).Build(ctx, n, c)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			pd, ok := d.(ports.ClientPacketDialer)
			if !ok {
				t.Fatal("UDP capability has no implementation")
			}
			echo, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			done := make(chan error, 1)
			go func() {
				b := make([]byte, 65536)
				size, addr, e := echo.ReadFrom(b)
				if e == nil {
					_, e = echo.WriteTo(b[:size], addr)
				}
				done <- e
			}()
			e := access.Endpoint{Host: "127.0.0.1", Port: uint16(echo.LocalAddr().(*net.UDPAddr).Port)}
			pc, err := pd.ListenPacket(ctx, e)
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
			payload := []byte("synthetic remote UDP")
			if _, err = pc.WriteTo(payload, echo.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 65536)
			size, _, err := pc.ReadFrom(buffer)
			if err != nil || !bytes.Equal(buffer[:size], payload) {
				t.Fatal("remote UDP", err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			local := freePort(t)
			addLocal(t, s, local, client.Direct)
			conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", portText(local)))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, err = conn.Write([]byte{5, 1, 0})
			if err != nil {
				t.Fatal(err)
			}
			auth := make([]byte, 2)
			if _, err = io.ReadFull(conn, auth); err != nil {
				t.Fatal(err)
			}
			_, _ = conn.Write([]byte{5, 3, 0, 1, 127, 0, 0, 1, 0, 0})
			reply := make([]byte, 10)
			if _, err = io.ReadFull(conn, reply); err != nil || reply[1] != 0 {
				t.Fatal("local UDP association must succeed", err)
			}
		})
	}
}
func portText(port uint16) string { return strconv.Itoa(int(port)) }

type clientCommitFailure struct {
	ports.ClientRepository
	fail atomic.Bool
}

func (r *clientCommitFailure) CommitOperation(ctx context.Context, op identity.Transaction, fn func(ports.Writer) error) error {
	return r.ClientRepository.CommitOperation(ctx, op, func(w ports.Writer) error {
		if err := fn(w); err != nil {
			return err
		}
		if r.fail.Load() {
			return identity.Err(identity.Unavailable, "synthetic commit failure after candidate write")
		}
		return nil
	})
}

func TestClientRestartCommitFailurePreservesSessionThenSuccessfulRestartClosesIt(t *testing.T) {
	ctx := context.Background()
	var repository *clientCommitFailure
	s, store := setupSnell(t, filepath.Join(t.TempDir(), "state", "state.db"), func(r ports.RuntimeRepository) ports.Repository {
		repository = &clientCommitFailure{ClientRepository: r.(ports.ClientRepository)}
		return repository
	})
	defer stop(t, s, store)
	enableClient(t, s)
	port := freePort(t)
	addLocal(t, s, port, client.Direct)
	target := echoTarget(t, "127.0.0.1")
	held, err := socksConn(port, target)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	check := func() {
		t.Helper()
		if _, err := held.Write([]byte("held")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 4)
		if _, err := io.ReadFull(held, b); err != nil || string(b) != "held" {
			t.Fatal("held session", err)
		}
	}
	check()
	before, _ := s.ClientStatus(ctx)
	b, _ := json.Marshal(application.ClientMutation{Resource: "runtime", Action: "restart"})
	p, err := s.PlanClient(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	repository.fail.Store(true)
	if _, err := s.ApplyClient(ctx, application.ApplyRequest{Document: b, Digest: p.Digest, Revision: p.Revision}); err == nil {
		t.Fatal("injected commit failure accepted")
	}
	after, err := s.ClientStatus(ctx)
	if err != nil || after.State.Revision != before.State.Revision || !after.State.Enabled || len(after.Sessions) != 1 {
		t.Fatal("failed restart changed committed or active state", err)
	}
	state, _ := store.State(ctx)
	if state.PendingTransactions != 0 {
		t.Fatal("failed restart leaked pending transaction")
	}
	check()
	if err := transfer(port, target, []byte("listener survived")); err != nil {
		t.Fatal(err)
	}
	repository.fail.Store(false)
	clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "restart"})
	_ = held.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := held.Read(make([]byte, 1)); err == nil {
		t.Fatal("restart retained old session")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("restart did not close held socket")
	}
	waitIdle(t, s)
	after, _ = s.ClientStatus(ctx)
	if after.State.Revision != before.State.Revision+1 || !after.State.Enabled {
		t.Fatal("restart was not one committed mutation")
	}
	if err := transfer(port, target, []byte("fresh session")); err != nil {
		t.Fatal(err)
	}
}
