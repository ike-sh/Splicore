package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
)

const (
	httpFirst  = "http-fixture-user-a93a"
	httpSecond = "http-fixture-user-b71e"
	httpAdded  = "http-fixture-user-c29c"
)

func httpCredential(user, password string) *application.CredentialInput {
	return &application.CredentialInput{Kind: access.UsernamePassword, Value: fmt.Sprintf(`{"username":%q,"password":%q}`, user, password)}
}

func proxyBasic(user, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
}

func requireHTTPProcessRedacted(t *testing.T, data []byte) {
	t.Helper()
	requireSocksRedacted(t, data)
	for _, fixture := range []string{httpFirst, httpSecond, httpAdded,
		proxyBasic(httpFirst, socksAlice), proxyBasic(httpSecond, socksBob),
		proxyBasic(httpFirst, socksRotated), proxyBasic(httpAdded, socksBob)} {
		if bytes.Contains(data, []byte(fixture)) {
			t.Fatal("ordinary Core output or persisted bytes contained proxy identity material")
		}
	}
}

type httpProcessListener struct {
	net.Listener
	accepted atomic.Int64
}

func (l *httpProcessListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return c, err
}

func httpTarget(t *testing.T, host string, handler http.Handler, tls bool) (*httptest.Server, *httpProcessListener) {
	t.Helper()
	raw, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	listener := &httpProcessListener{Listener: raw}
	s := httptest.NewUnstartedServer(handler)
	_ = s.Listener.Close()
	s.Listener = listener
	if tls {
		s.StartTLS()
	} else {
		s.Start()
	}
	t.Cleanup(s.Close)
	return s, listener
}

func TestManagedHTTPProxyProcesses(t *testing.T) {
	core := os.Getenv("SPLICORE_RUNTIME_BINARY")
	if core == "" {
		t.Skip("set SPLICORE_RUNTIME_BINARY to the native built core to run process qualification")
	}
	if !filepath.IsAbs(core) {
		t.Fatal("native binary path must be absolute")
	}
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Fatal("independent curl peer unavailable:", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 55*time.Second)
	defer cancel()
	server := newProxyProcessCore(t, core, requireHTTPProcessRedacted)
	local := newProxyProcessCore(t, core, requireHTTPProcessRedacted)
	stopServer, stopLocal := server.start(ctx), local.start(ctx)
	serverPort := testkit.PeerPort(t, "tcp")
	serverAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort))
	proxyURL := "http://" + serverAddr
	draft := server.file("http.json", fmt.Appendf(nil, `{
		"schema":1,"name":"Managed HTTP fixture","listener":{"port":%d},"settings":{"auth":true},
		"users":[{"account_name":"A","username":%q,"password":%q},
		{"account_name":"B","username":%q,"password":%q,"enabled":false},
		{"account_name":"Expired","username":"http-fixture-expired","password":%q,"expires_at":"2001-01-01T00:00:00Z"}]}`,
		serverPort, httpFirst, socksAlice, httpSecond, socksBob, socksBob))
	server.cli(ctx, "check", "--protocol", "http", "--file", draft)
	apply := func() []string {
		plan := server.file("http.plan", server.cli(ctx, "inbound", "plan", "--protocol", "http", "--file", draft))
		return []string{"inbound", "apply", "--protocol", "http", "--file", draft, "--plan", plan}
	}
	t.Run("port-conflict", func(t *testing.T) {
		occupied, err := net.Listen("tcp4", serverAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer occupied.Close()
		data, err := server.command(ctx, apply()...)
		requireHTTPProcessRedacted(t, data)
		if err == nil || !bytes.Contains(data, []byte("port_conflict")) {
			t.Fatal("occupied port did not reject managed creation")
		}
		snapshot, err := server.control.Inbounds(ctx)
		if err != nil || len(snapshot.Items) != 0 {
			t.Fatal("failed listener creation committed resources")
		}
	})
	var created application.CreationResult
	if err = json.Unmarshal(server.cli(ctx, apply()...), &created); err != nil || len(created.Bindings) != 3 {
		t.Fatal("managed creation did not persist three bindings")
	}
	id, first, second := created.InboundID, created.Bindings[0].BindingID, created.Bindings[1].BindingID
	in, _ := server.view(ctx, id)
	if in.Inbound.Protocol != proxy.Key("http") || in.Inbound.Listeners[0].Endpoint.Host != "127.0.0.1" || in.Health != "healthy" {
		t.Fatal("managed HTTP listener did not start on loopback")
	}

	const query = "q=a%2Bb"
	payload := bytes.Repeat([]byte("synthetic-http-stream-"), 6144)
	origin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "/fixture?"+query || r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Proxy-Connection") != "" ||
			r.Header.Get("X-Hop") != "" || r.Header.Get("X-Fixture") != "retained" {
			w.WriteHeader(422)
			return
		}
		w.Header().Set("X-Fixture-Response", r.Method)
		if r.Method == "POST" || r.Method == "PUT" {
			data, err := io.ReadAll(io.LimitReader(r.Body, int64(len(payload)+1)))
			if err != nil || !bytes.Equal(data, payload) || r.Method == "PUT" && len(r.TransferEncoding) == 0 {
				w.WriteHeader(422)
				return
			}
		}
		w.WriteHeader(203)
		if r.Method != "HEAD" {
			_, _ = w.Write(payload)
		}
	})
	v4, v4listener := httpTarget(t, "127.0.0.1", origin, false)
	v6, _ := httpTarget(t, "::1", origin, false)
	tlsOrigin, tlsListener := httpTarget(t, "127.0.0.1", origin, true)
	domainURL := strings.Replace(v4.URL, "127.0.0.1", "localhost", 1)
	conf := server.file("curl.conf", fmt.Appendf(nil, "proxy-user = %q\n", httpFirst+":"+socksAlice))
	headers := filepath.Join(server.root, "curl-headers.txt")
	bodyFile := server.file("fixture-payload", payload)
	execCurl := func(proxy, conf, method, target string, args ...string) ([]byte, []byte, error) {
		t.Helper()
		opts := []string{"-q", "--silent", "--show-error", "--fail-with-body", "--noproxy", "", "--max-time", "7",
			"--http1.1", "--proxy", proxy, "--dump-header", headers, "--request", method,
			"-H", "X-Fixture: retained"}
		if conf != "" {
			opts = append(opts, "--config", conf, "--proxy-basic")
		}
		opts = append(opts, args...)
		out, err := exec.CommandContext(ctx, curl, append(opts, target+"/fixture?"+query)...).CombinedOutput()
		fields, readErr := os.ReadFile(headers)
		if readErr != nil {
			t.Fatal("missing curl response headers:", readErr, err)
		}
		return out, fields, err
	}

	t.Run("curl-forward", func(t *testing.T) {
		for _, tc := range []struct {
			method, target string
			options        []string
		}{
			{"GET", domainURL, nil},
			{"HEAD", v6.URL, []string{"--head"}},
			{"POST", v4.URL, []string{"--data-binary", "@" + bodyFile}},
			{"PUT", v4.URL, []string{"--data-binary", "@" + bodyFile, "-H", "Transfer-Encoding: chunked"}},
			{"DELETE", v6.URL, nil},
		} {
			opts := append([]string{"-H", "Connection: X-Hop", "-H", "X-Hop: stripped"}, tc.options...)
			data, header, err := execCurl(proxyURL, conf, tc.method, tc.target, opts...)
			if err != nil || !bytes.Contains(header, []byte(" 203 ")) ||
				!strings.Contains(strings.ToLower(string(header)), "x-fixture-response: "+strings.ToLower(tc.method)) {
				t.Fatalf("curl %s did not receive forwarded status and headers: %v (%s)", tc.method, err, header)
			}
			if tc.method != "HEAD" && !bytes.Equal(data, payload) {
				t.Fatalf("curl %s transferred %d bytes, expected %d", tc.method, len(data), len(payload))
			}
		}
	})
	t.Run("curl-connect", func(t *testing.T) {
		// The owned origin uses httptest's self-signed certificate. Curl handles
		// TLS end-to-end after verifying this proxy's actual CONNECT exchange.
		data, header, err := execCurl(proxyURL, conf, "GET", tlsOrigin.URL, "--insecure")
		if err != nil || !bytes.Equal(data, payload) || !bytes.Contains(header, []byte("200 Connection Established")) ||
			!bytes.Contains(header, []byte(" 203 ")) || tlsListener.accepted.Load() != 1 {
			t.Fatalf("independent curl TLS tunnel failed: %v (%s)", err, header)
		}
		_, header, err = execCurl(proxyURL, "", "GET", tlsOrigin.URL, "--insecure")
		if err == nil || !bytes.Contains(header, []byte(" 407 ")) || tlsListener.accepted.Load() != 1 {
			t.Fatal("unauthenticated curl CONNECT reached the TLS origin")
		}
	})

	t.Run("scoped-direct-and-reject", func(t *testing.T) {
		ruleID, err := identity.NewID()
		if err != nil {
			t.Fatal(err)
		}
		route := func(kind P.ActionKind) {
			server.mutation(ctx, application.ClientMutation{Resource: "network", Action: "replace",
				Network: &P.Config{Route: P.RouteProfile{Rules: []P.RouteRule{{
					ID: ruleID, Name: "HTTP target fixture", Match: P.RuleMatch{ServerInbounds: []identity.ID{id}}, Action: P.Action{Kind: kind},
				}}}}})
		}
		route(P.Reject)
		server.cli(ctx, "client", "start")
		before := v4listener.accepted.Load()
		_, header, err := execCurl(proxyURL, conf, "GET", v4.URL)
		if err == nil || !bytes.Contains(header, []byte(" 502 ")) || v4listener.accepted.Load() != before {
			t.Fatal("Core route rejection reached the destination")
		}
		route(P.Direct)
		data, header, err := execCurl(proxyURL, conf, "GET", v4.URL)
		if err != nil || !bytes.Contains(header, []byte(" 203 ")) || !bytes.Equal(data, payload) || v4listener.accepted.Load() != before+1 {
			t.Fatal("Core direct route did not reach the protected target")
		}
		server.mutation(ctx, application.ClientMutation{Resource: "network", Action: "replace", Network: &P.Config{}})
		server.cli(ctx, "client", "stop")
	})

	check407 := func(user, password string) {
		t.Helper()
		before := v4listener.accepted.Load()
		conn, err := net.DialTimeout("tcp4", serverAddr, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		_, err = fmt.Fprintf(conn, "GET %s/fixture?%s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
			v4.URL, query, strings.TrimPrefix(v4.URL, "http://"), proxyBasic(user, password))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "GET"})
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 407 || resp.Header.Get("Proxy-Authenticate") != `Basic realm="Splicore"` ||
			v4listener.accepted.Load() != before {
			t.Fatal("ineligible user was admitted or reached the destination")
		}
	}
	check407(httpSecond, socksBob)
	check407("http-fixture-expired", socksBob)

	node := local.mutation(ctx, application.ClientMutation{Resource: "node", Action: "create",
		Node: &client.RemoteNode{Name: "Managed HTTP upstream", Protocol: proxy.Key("http"),
			Endpoint: access.Endpoint{Host: "127.0.0.1", Port: uint16(serverPort)}, Transport: client.Transport{Kind: "tcp"},
			Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: json.RawMessage(`{"auth":true}`)},
		}, Credential: httpCredential(httpFirst, socksAlice)})
	outbound := local.mutation(ctx, application.ClientMutation{Resource: "outbound", Action: "create",
		Outbound: &client.Outbound{Name: "HTTP CONNECT upstream", Kind: "proxy", Engine: "native", NodeID: &node}})
	localPorts := map[string]int{}
	for _, kind := range []string{"socks5", "http"} {
		port := testkit.PeerPort(t, "tcp")
		localPorts[kind] = port
		local.mutation(ctx, application.ClientMutation{Resource: "local-inbound", Action: "create",
			LocalInbound: &client.LocalInbound{Name: "Application " + kind, Kind: kind, SelectedOutbound: outbound,
				Listen: access.Endpoint{Host: "127.0.0.1", Port: uint16(port)}}})
	}
	local.cli(ctx, "client", "start")
	t.Run("local-http-entry", func(t *testing.T) {
		url := "http://127.0.0.1:" + strconv.Itoa(localPorts["http"])
		data, header, err := execCurl(url, "", "GET", domainURL)
		if err != nil || !bytes.Contains(header, []byte(" 203 ")) || !bytes.Equal(data, payload) {
			t.Fatalf("local HTTP entry through HTTP outbound failed: %v (%s)", err, header)
		}
	})

	binding := func(idToChange identity.ID, action string, enabled bool, credential *application.CredentialInput) {
		t.Helper()
		in, revision := server.view(ctx, id)
		for _, b := range in.Bindings {
			if b.BindingID == idToChange {
				server.mutateInbound(ctx, "binding", id, application.BindingRequest{
					BindingID: b.BindingID, Action: action, Enabled: enabled, Credential: credential, Revision: revision, ResourceRevision: b.Revision,
				})
				return
			}
		}
		t.Fatal("binding missing")
	}
	lifecycle := func(action string) {
		t.Helper()
		in, revision := server.view(ctx, id)
		server.mutateInbound(ctx, "lifecycle", id, application.ManagedProxyLifecycleRequest{Action: action, Revision: revision, ResourceRevision: in.Inbound.Revision})
	}

	t.Run("two-core-outbound-and-recovery", func(t *testing.T) {
		target := socksHalfCloseTarget(t, "127.0.0.1")
		targetAddr := net.JoinHostPort("localhost", strconv.Itoa(int(target)))
		data := []byte("two independent Core processes and HTTP CONNECT")
		localAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(localPorts["socks5"]))
		chain := func(status byte) *net.TCPConn {
			conn := openSocksFixture(t, localAddr, "", "", 0)
			socksFixtureConnect(t, conn, "localhost", target, status)
			return conn
		}
		active := chain(0)
		view, _ := server.view(ctx, id)
		if view.Stats.Active != 1 || len(view.Sessions) != 1 || view.Sessions[0].Mode != "connect" || view.Sessions[0].BindingID != first {
			t.Fatal("active CONNECT missing authenticated binding ownership")
		}
		for _, b := range view.Bindings {
			if b.BindingID == first && (b.Stats.Upload <= int64(len(payload)) || b.Stats.Download <= int64(len(payload)) || b.Stats.Active != 1) ||
				b.BindingID == second && b.Stats.Sessions != 0 {
				t.Fatal("HTTP flow bytes or sessions attributed to the wrong binding")
			}
		}
		socksFixtureTransfer(t, active, data)
		active = chain(0)
		binding(first, "", false, nil)
		var one [1]byte
		if _, err := active.Read(one[:]); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal("disabled binding did not close its generation's tunnel")
		}
		_ = active.Close()
		check407(httpFirst, socksAlice)
		_ = chain(1).Close()
		binding(first, "", true, nil)
		binding(first, "rotate", true, httpCredential(httpFirst, socksRotated))
		check407(httpFirst, socksAlice)
		_ = chain(1).Close()
		local.mutation(ctx, application.ClientMutation{Resource: "node", Action: "rotate", ID: node, Credential: httpCredential(httpFirst, socksRotated)})
		socksFixtureTransfer(t, chain(0), data)

		in, revision := server.view(ctx, id)
		server.mutateInbound(ctx, "binding", id, map[string]any{
			"action": "add", "revision": revision, "resource_revision": in.Inbound.Revision,
			"user": map[string]any{"account_name": "Enrolled", "username": httpAdded, "password": socksBob},
		})
		in, _ = server.view(ctx, id)
		var added identity.ID
		for _, b := range in.Bindings {
			if b.BindingID != first && b.BindingID != second && b.BindingID != created.Bindings[2].BindingID && b.Enabled {
				added = b.BindingID
			}
		}
		if len(in.Bindings) != 4 || added == "" {
			t.Fatal("HTTP enrollment failed")
		}
		// Use an independent wire CONNECT with header and early TCP payload
		// coalesced to check handoff, attribution and both half-closes.
		client, err := net.DialTimeout("tcp4", serverAddr, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		tcp := client.(*net.TCPConn)
		defer tcp.Close()
		_ = tcp.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = fmt.Fprintf(tcp, "CONNECT %[1]s HTTP/1.1\r\nHost: %[1]s\r\nProxy-Authorization: Basic %s\r\n\r\n%s", targetAddr, proxyBasic(httpAdded, socksBob), data)
		if err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(tcp)
		resp, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
		if err != nil || resp.StatusCode != 200 {
			t.Fatal("enrolled binding did not establish CONNECT")
		}
		// Read raw bytes from the buffered CONNECT reader, not Response.Body.
		if err = tcp.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(io.LimitReader(reader, int64(len(data)+1)))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatal("early tunnel bytes or half-close failed")
		}
		in, _ = server.view(ctx, id)
		for _, b := range in.Bindings {
			if b.BindingID == added && (b.Stats.TCPSessions != 1 || b.Stats.Upload != int64(len(data)) || b.Stats.Download != int64(len(data))) {
				t.Fatal("enrolled user CONNECT bytes were not attributed")
			}
		}
		binding(added, "revoke", false, nil)
		check407(httpAdded, socksBob)

		active = chain(0)
		lifecycle("stop")
		if _, err := active.Read(one[:]); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal("stopped listener left an established tunnel running")
		}
		_ = active.Close()
		free, err := net.Listen("tcp4", serverAddr)
		if err != nil {
			t.Fatal("stopped inbound did not release owned port")
		}
		_ = free.Close()
		stopServer()
		stopServer = server.start(ctx)
		in, _ = server.view(ctx, id)
		if in.Health != "stopped" || in.Inbound.Enabled {
			t.Fatal("stopped HTTP listener did not survive restart")
		}
		lifecycle("start")
		check407(httpAdded, socksBob)
		check407(httpFirst, socksAlice)
		stopServer()
		stopServer = server.start(ctx)
		stopLocal()
		stopLocal = local.start(ctx)
		socksFixtureTransfer(t, chain(0), data)
		binding(added, "delete", false, nil)
		check407(httpAdded, socksBob)
		lifecycle("delete")
		if _, err := server.control.Inbound(ctx, id); err == nil {
			t.Fatal("deleted HTTP listener remained queryable")
		}
		if c, err := net.DialTimeout("tcp4", serverAddr, time.Second); err == nil {
			_ = c.Close()
			t.Fatal("deleted HTTP listener still accepted connections")
		}
	})

	stopLocal()
	stopServer()
	for _, process := range []*proxyProcessCore{local, server} {
		state, err := os.ReadFile(filepath.Join(process.root, "state", "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		requireHTTPProcessRedacted(t, state)
	}
}
