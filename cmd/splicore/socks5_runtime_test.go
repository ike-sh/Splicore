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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
)

const socksAlice = "Synthetic-Alice-Secret!349"
const socksBob = "Synthetic-Bob-Secret!582"
const socksRotated = "Synthetic-Rotated-Secret!691"

type socksCore struct {
	t          *testing.T
	binary     string
	root       string
	bootstrap  string
	control    *transport.Client
	generation int
}

func newSocksCore(t *testing.T, binary string) *socksCore {
	t.Helper()
	// Short enough for the Unix socket length limit and owned by this test.
	root, err := os.MkdirTemp("", "sp-s5-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	state := filepath.ToSlash(filepath.Join(root, "state"))
	key := filepath.ToSlash(filepath.Join(root, "key", "master.key"))
	socket := filepath.ToSlash(filepath.Join(root, "ctl", "core.sock"))
	core := &socksCore{t: t, binary: binary, root: root, control: transport.UnixClient(socket)}
	t.Cleanup(core.control.Close)
	core.bootstrap = core.file("bootstrap.yaml", []byte(fmt.Sprintf("schema: 1\nstate_directory: %q\nkey_file: %q\napi:\n  unix_socket: %q\n", state, key, socket)))
	core.cli(t.Context(), "key", "init", "--file", key)
	return core
}

func (c *socksCore) file(name string, data []byte) string {
	c.t.Helper()
	path := filepath.Join(c.root, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		c.t.Fatal(err)
	}
	return path
}

func (c *socksCore) command(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, c.binary, append(args, "--config", c.bootstrap)...).CombinedOutput()
}

func (c *socksCore) cli(ctx context.Context, args ...string) []byte {
	c.t.Helper()
	data, err := c.command(ctx, args...)
	if len(args) < 2 || args[0] != "inbound" || args[1] != "export" {
		requireSocksRedacted(c.t, data)
	}
	if err != nil {
		c.t.Fatalf("SOCKS5 process CLI %s failed: %v", args[0], err)
	}
	return data
}

func requireSocksRedacted(t *testing.T, data []byte) {
	t.Helper()
	for _, password := range []string{socksAlice, socksBob, socksRotated} {
		if bytes.Contains(data, []byte(password)) {
			t.Fatal("ordinary output or stored bytes contained a fixture password")
		}
	}
}

func (c *socksCore) start(ctx context.Context) func() {
	c.t.Helper()
	c.generation++
	log, err := os.OpenFile(filepath.Join(c.root, fmt.Sprintf("core-%d.log", c.generation)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		c.t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, c.binary, "run", "--config", c.bootstrap)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		_ = log.Close()
		c.t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	joined := false
	c.t.Cleanup(func() {
		if !joined {
			_ = cmd.Process.Kill()
			<-done
		}
		_ = log.Close()
	})
	ready, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	tick := time.NewTicker(15 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := c.control.System(ready); err == nil {
			break
		}
		select {
		case err := <-done:
			joined = true
			data, _ := os.ReadFile(log.Name())
			requireSocksRedacted(c.t, data)
			c.t.Fatalf("SOCKS5 Core exited before ready: %v: %s", err, data)
		case <-ready.Done():
			c.t.Fatal("SOCKS5 Core readiness timed out")
		case <-tick.C:
		}
	}
	c.cli(ctx, "status")
	return func() {
		c.t.Helper()
		c.cli(ctx, "stop")
		select {
		case err := <-done:
			joined = true
			if err != nil {
				c.t.Fatal("SOCKS5 Core shutdown failed:", err)
			}
		case <-ctx.Done():
			c.t.Fatal("SOCKS5 Core process did not stop")
		}
		_ = log.Close()
		data, err := os.ReadFile(log.Name())
		if err != nil {
			c.t.Fatal(err)
		}
		requireSocksRedacted(c.t, data)
	}
}

func (c *socksCore) mutation(ctx context.Context, mutation application.ClientMutation) identity.ID {
	c.t.Helper()
	doc, err := json.Marshal(mutation)
	if err != nil {
		c.t.Fatal(err)
	}
	file := c.file(mutation.Resource+".json", doc)
	plan := c.file(mutation.Resource+".plan", c.cli(ctx, mutation.Resource, "plan", "--file", file))
	result := c.cli(ctx, mutation.Resource, "apply", "--file", file, "--plan", plan)
	var created application.ClientResult
	if err := json.Unmarshal(result, &created); err != nil {
		c.t.Fatal(err)
	}
	return created.ID
}

func (c *socksCore) mutateInbound(ctx context.Context, verb string, id identity.ID, doc any) {
	c.t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		c.t.Fatal(err)
	}
	c.cli(ctx, "inbound", verb, "--id", string(id), "--file", c.file(verb+".json", data))
}

func (c *socksCore) view(ctx context.Context, id identity.ID) (application.InboundView, identity.Revision) {
	c.t.Helper()
	var in application.InboundView
	if err := json.Unmarshal(c.cli(ctx, "inbound", "get", "--id", string(id)), &in); err != nil {
		c.t.Fatal(err)
	}
	page, err := c.control.Inbounds(ctx)
	if err != nil {
		c.t.Fatal(err)
	}
	return in, page.Revision
}

func openSocksFixture(t *testing.T, address string, username, password string, authStatus byte) *net.TCPConn {
	t.Helper()
	raw, err := net.DialTimeout("tcp4", address, 3*time.Second)
	if err != nil {
		t.Fatal("fixture listener:", err)
	}
	conn := raw.(*net.TCPConn)
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	method := byte(0)
	if username != "" {
		method = 2
	}
	writeSocksFixture(t, conn, []byte{5, 1, method})
	readSocksFixture(t, conn, []byte{5, method})
	if method == 2 {
		credentials := append([]byte{1, byte(len(username))}, username...)
		credentials = append(append(credentials, byte(len(password))), password...)
		// Send several segments without sharing the product's SOCKS codec.
		for _, octet := range credentials {
			writeSocksFixture(t, conn, []byte{octet})
		}
		clear(credentials)
		readSocksFixture(t, conn, []byte{1, authStatus})
	}
	return conn
}

func writeSocksFixture(t *testing.T, conn net.Conn, data []byte) {
	t.Helper()
	if _, err := io.Copy(conn, bytes.NewReader(data)); err != nil {
		t.Fatal("fixture socket write:", err)
	}
}

func readSocksFixture(t *testing.T, conn net.Conn, want []byte) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("fixture protocol or payload mismatch, length %d: %v", len(want), err)
	}
}

func socksFixtureConnect(t *testing.T, conn net.Conn, host string, port uint16, code byte) {
	t.Helper()
	frame := []byte{5, 1, 0}
	switch ip := net.ParseIP(host); {
	case ip == nil:
		frame = append(append(frame, 3, byte(len(host))), host...)
	case ip.To4() != nil:
		frame = append(append(frame, 1), ip.To4()...)
	default:
		frame = append(append(frame, 4), ip.To16()...)
	}
	writeSocksFixture(t, conn, binary.BigEndian.AppendUint16(frame, port))
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil || header[0] != 5 || header[1] != code || header[2] != 0 {
		t.Fatalf("fixture CONNECT reply %v, expected status %d: %v", header, code, err)
	}
	size := 4
	if header[3] == 4 {
		size = 16
	} else if header[3] != 1 {
		t.Fatal("fixture CONNECT response had invalid address type")
	}
	if _, err := io.CopyN(io.Discard, conn, int64(size+2)); err != nil {
		t.Fatal(err)
	}
}

func socksHalfCloseTarget(t *testing.T, host string) uint16 {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP(host)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
				data, err := io.ReadAll(io.LimitReader(conn, 16385))
				if err == nil {
					_, _ = conn.Write(data)
					_ = conn.CloseWrite()
				}
			}()
		}
	}()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

func socksFixtureTransfer(t *testing.T, conn *net.TCPConn, body []byte) {
	t.Helper()
	defer conn.Close()
	writeSocksFixture(t, conn, body)
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	readSocksFixture(t, conn, body)
	var extra [1]byte
	if _, err := conn.Read(extra[:]); err != io.EOF {
		t.Fatal("target half-close did not propagate back to the client:", err)
	}
}

func TestManagedSOCKS5Processes(t *testing.T) {
	core := os.Getenv("SPLICORE_RUNTIME_BINARY")
	if core == "" {
		t.Skip("set SPLICORE_RUNTIME_BINARY to the native built core to run process qualification")
	}
	if !filepath.IsAbs(core) {
		t.Fatal("native binary path must be absolute")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 55*time.Second)
	defer cancel()
	server, local := newSocksCore(t, core), newSocksCore(t, core)
	stopServer := server.start(ctx)
	stopLocal := local.start(ctx)
	serverPort := testkit.PeerPort(t, "tcp")
	localPort := testkit.PeerPort(t, "tcp")
	serverAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort))
	localAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort))
	v4, v6 := socksHalfCloseTarget(t, "127.0.0.1"), socksHalfCloseTarget(t, "::1")
	body := bytes.Repeat([]byte("SOCKS5 owned fixture"), 128)
	draft := server.file("socks5.json", fmt.Appendf(nil, `{
		"schema":1,"name":"managed SOCKS5 fixture","listener":{"port":%d},"settings":{"auth":true},
		"users":[{"account_name":"first","username":"alice","password":%q},
		{"account_name":"second","username":"bob","password":%q},
		{"account_name":"disabled","username":"disabled","password":%q,"enabled":false},
		{"account_name":"expired","username":"expired","password":%q,"expires_at":"2001-01-01T00:00:00Z"}]}`,
		serverPort, socksAlice, socksBob, socksBob, socksBob))
	server.cli(ctx, "check", "--protocol", "socks5", "--file", draft)
	plan := server.file("socks5.plan", server.cli(ctx, "inbound", "plan", "--protocol", "socks5", "--file", draft))
	raw := server.cli(ctx, "inbound", "apply", "--protocol", "socks5", "--file", draft, "--plan", plan)
	var created application.CreationResult
	if err := json.Unmarshal(raw, &created); err != nil || len(created.Bindings) != 4 {
		t.Fatal("invalid managed SOCKS5 creation result")
	}
	id, first, second := created.InboundID, created.Bindings[0].BindingID, created.Bindings[1].BindingID
	server.cli(ctx, "inbound", "list")
	in, _ := server.view(ctx, id)
	if in.Health != "healthy" || in.Inbound.Listeners[0].Endpoint.Host != "127.0.0.1" {
		t.Fatal("default listener is not healthy loopback")
	}
	export := func(binding identity.ID) ([]byte, error) {
		return server.command(ctx, "inbound", "export", "--id", string(id), "--binding-id", string(binding), "--format", "mihomo", "--client-version", "1.19.32")
	}
	data, err := export(first)
	var result application.ExportResult
	var profile struct {
		Proxies []struct {
			Type     string `json:"type"`
			Server   string `json:"server"`
			Port     int    `json:"port"`
			Username string `json:"username"`
			Password string `json:"password"`
			UDP      *bool  `json:"udp"`
		} `json:"proxies"`
	}
	if err != nil || json.Unmarshal(data, &result) != nil || json.Unmarshal([]byte(result.Content), &profile) != nil || len(profile.Proxies) != 1 {
		t.Fatal("authorized managed SOCKS5 export failed")
	}
	peer := profile.Proxies[0]
	if peer.Type != "socks5" || peer.Server != "127.0.0.1" || peer.Port != serverPort || peer.Username != "alice" || peer.Password != socksAlice || peer.UDP == nil || *peer.UDP {
		t.Fatal("export did not retain the authorized TCP-only client profile")
	}
	for _, binding := range []identity.ID{"", created.Bindings[2].BindingID, created.Bindings[3].BindingID} {
		data, err := export(binding)
		requireSocksRedacted(t, data)
		if err == nil {
			t.Fatal("ambiguous, disabled or expired binding export was accepted")
		}
	}

	t.Run("independent-wire-client", func(t *testing.T) {
		for _, flow := range []struct {
			host, user, password string
			port                 uint16
		}{
			{"127.0.0.1", "alice", socksAlice, v4}, {"::1", "bob", socksBob, v6}, {"localhost", "alice", socksAlice, v4},
		} {
			t.Run(flow.host, func(t *testing.T) {
				t.Parallel()
				conn := openSocksFixture(t, serverAddr, flow.user, flow.password, 0)
				socksFixtureConnect(t, conn, flow.host, flow.port, 0)
				socksFixtureTransfer(t, conn, body)
			})
		}
	})
	for _, user := range []string{"missing", "disabled", "expired"} {
		_ = openSocksFixture(t, serverAddr, user, socksBob, 1).Close()
	}
	in, _ = server.view(ctx, id)
	for _, b := range in.Bindings {
		count := map[identity.ID]int64{first: 2, second: 1}[b.BindingID]
		want := count * int64(len(body))
		if b.Stats.Upload != want || b.Stats.Download != want || b.Stats.TCPSessions != count {
			t.Fatal("the expected TCP payload was not attributed to its managed binding")
		}
	}

	t.Run("reverse-half-close-and-abort", func(t *testing.T) {
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		open := func() (*net.TCPConn, *net.TCPConn) {
			conn := openSocksFixture(t, serverAddr, "alice", socksAlice, 0)
			socksFixtureConnect(t, conn, "127.0.0.1", uint16(listener.Addr().(*net.TCPAddr).Port), 0)
			peer, err := listener.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = peer.Close() })
			if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			return conn, peer
		}
		conn, peer := open()
		writeSocksFixture(t, peer, body)
		if err := peer.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		readSocksFixture(t, conn, body)
		var extra [1]byte
		if _, err := conn.Read(extra[:]); err != io.EOF {
			t.Fatal("target's first half-close did not reach the client", err)
		}
		writeSocksFixture(t, conn, body)
		if err := conn.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		readSocksFixture(t, peer, body)
		if _, err := peer.Read(extra[:]); err != io.EOF {
			t.Fatal("client could not finish upload after receiving EOF", err)
		}

		conn, peer = open()
		if err := peer.SetLinger(0); err != nil {
			t.Fatal(err)
		}
		if err := peer.Close(); err != nil {
			t.Fatal(err)
		}
		_, err = conn.Read(extra[:])
		var timeout net.Error
		if err == nil || errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatal("aborted target did not release the client flow")
		}
	})

	pair := func(password string) *application.CredentialInput {
		return &application.CredentialInput{Kind: access.UsernamePassword, Value: fmt.Sprintf(`{"username":"alice","password":%q}`, password)}
	}
	node := local.mutation(ctx, application.ClientMutation{Resource: "node", Action: "create",
		Node: &client.RemoteNode{Name: "SOCKS5 upstream", Protocol: proxy.Key("socks5"),
			Endpoint: access.Endpoint{Host: "127.0.0.1", Port: uint16(serverPort)}, Transport: client.Transport{Kind: "tcp"},
			Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: json.RawMessage(`{"auth":true,"udp":false}`)},
		}, Credential: pair(socksAlice)})
	outbound := local.mutation(ctx, application.ClientMutation{Resource: "outbound", Action: "create",
		Outbound: &client.Outbound{Name: "SOCKS5 chain", Kind: "proxy", Engine: "native", NodeID: &node}})
	local.mutation(ctx, application.ClientMutation{Resource: "local-inbound", Action: "create",
		LocalInbound: &client.LocalInbound{Name: "SOCKS5 application ingress", Kind: "socks5", SelectedOutbound: outbound,
			Listen: access.Endpoint{Host: "127.0.0.1", Port: uint16(localPort)}}})
	local.cli(ctx, "client", "start")

	binding := func(action string, enabled bool, credential *application.CredentialInput) {
		in, revision := server.view(ctx, id)
		for _, b := range in.Bindings {
			if b.BindingID == first {
				server.mutateInbound(ctx, "binding", id, application.BindingRequest{
					Action: action, Enabled: enabled, BindingID: first, Credential: credential, Revision: revision, ResourceRevision: b.Revision,
				})
				return
			}
		}
		t.Fatal("managed binding missing")
	}
	lifecycle := func(action string) {
		in, revision := server.view(ctx, id)
		server.mutateInbound(ctx, "lifecycle", id, application.SOCKS5LifecycleRequest{Action: action, Revision: revision, ResourceRevision: in.Inbound.Revision})
	}

	t.Run("two-core-outbound-and-restart", func(t *testing.T) {
		chain := func(want byte) *net.TCPConn {
			conn := openSocksFixture(t, localAddr, "", "", 0)
			socksFixtureConnect(t, conn, "localhost", v4, want)
			return conn
		}
		socksFixtureTransfer(t, chain(0), body)
		binding("", false, nil)
		_ = openSocksFixture(t, serverAddr, "alice", socksAlice, 1).Close()
		data, err := export(first)
		requireSocksRedacted(t, data)
		if err == nil {
			t.Fatal("disabled binding remained exportable")
		}
		_ = chain(1).Close()
		binding("", true, nil)
		socksFixtureTransfer(t, chain(0), body)
		binding("rotate", true, pair(socksRotated))
		_ = chain(1).Close()
		local.mutation(ctx, application.ClientMutation{Resource: "node", Action: "rotate", ID: node, Credential: pair(socksRotated)})
		socksFixtureTransfer(t, chain(0), body)

		active := chain(0)
		lifecycle("stop")
		var one [1]byte
		_, err = active.Read(one[:])
		var timeout net.Error
		if err == nil || errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatal("stopped server did not release active flow")
		}
		_ = active.Close()
		lease, err := net.Listen("tcp4", serverAddr)
		if err != nil {
			t.Fatal("stopped server did not release listener:", err)
		}
		_ = lease.Close()
		stopServer()
		stopServer = server.start(ctx)
		in, _ := server.view(ctx, id)
		if in.Health != "stopped" || in.Inbound.Enabled {
			t.Fatal("stopped intent did not survive restart")
		}
		binding("", false, nil)
		lifecycle("start")
		_ = chain(1).Close()
		binding("", true, nil)
		stopLocal()
		stopLocal = local.start(ctx)
		socksFixtureTransfer(t, chain(0), body)
		binding("delete", false, nil)
		_ = chain(1).Close()
		lifecycle("delete")
		if _, err := server.control.Inbound(ctx, id); err == nil {
			t.Fatal("deleted SOCKS5 inbound remains queryable")
		}
	})
	stopLocal()
	stopServer()
	for _, core := range []*socksCore{local, server} {
		for _, file := range []string{"state.db", "state.db-wal"} {
			data, err := os.ReadFile(filepath.Join(core.root, "state", file))
			if errors.Is(err, os.ErrNotExist) && file == "state.db-wal" {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			requireSocksRedacted(t, data)
		}
	}
}
