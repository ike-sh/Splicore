package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/native"
	"github.com/ike-sh/Splicore/internal/splicore/nodeimport"
	httpproxy "github.com/ike-sh/Splicore/internal/splicore/protocol/http"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks5"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func enableProxyInterfaces(t *testing.T, s *application.Service, journal ...string) {
	t.Helper()
	r, e := registry.NewOutbounds(native.SOCKS5OutboundFactory{}, native.HTTPOutboundFactory{})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.EnableClientRuntime(context.Background(), r, journal...); e != nil {
		t.Fatal(e)
	}
}

// Explicit echo I/O keeps the stdlib TCP splice pipe pool out of this fixture's
// descriptor accounting. All accepted targets are joined before test cleanup.
func phase20Echo(t *testing.T) access.Endpoint {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
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
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				b := make([]byte, 32768)
				for {
					n, e := c.Read(b)
					if n > 0 {
						if socks5.WriteFull(c, b[:n]) != nil {
							return
						}
					}
					if e != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = l.Close(); wg.Wait() })
	return access.Endpoint{Host: "127.0.0.1", Port: uint16(l.Addr().(*net.TCPAddr).Port)}
}
func proxyAuthInput(password string) *application.CredentialInput {
	b, _ := json.Marshal(map[string]string{"username": "synthetic", "password": password})
	return &application.CredentialInput{Kind: access.UsernamePassword, Value: string(b)}
}
func createProxyListener(t *testing.T, s *application.Service, kind string, auth bool) (client.LocalInbound, identity.ID) {
	t.Helper()
	i := client.LocalInbound{Name: "Phase20 " + kind, Kind: kind, Listen: access.Endpoint{Host: "127.0.0.1", Port: freePort(t)}, Auth: auth}
	result := clientApply(t, s, application.ClientMutation{Resource: "local-inbound", Action: "create", LocalInbound: &i})
	i.ID = result.ID
	if !auth {
		return i, ""
	}
	state, e := s.ClientStatus(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	reqid, _ := identity.NewID()
	a, _, e := s.CreateAccount(context.Background(), "Phase20 synthetic account", state.State.Revision, identity.Actor{Principal: "local-test", RequestID: reqid})
	if e != nil {
		t.Fatal(e)
	}
	result = clientApply(t, s, application.ClientMutation{Resource: "local-binding", Action: "create", Binding: &access.Binding{AccountID: a.ID, InboundID: i.ID, Enabled: true}, Credential: proxyAuthInput("fixture")})
	return i, result.ID
}
func phase20Stream(t *testing.T, i client.LocalInbound, target access.Endpoint, password string) {
	t.Helper()
	c, e := net.DialTimeout("tcp", net.JoinHostPort(i.Listen.Host, fmt.Sprint(i.Listen.Port)), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	var pair *socks5.Credentials
	if i.Auth {
		pair = &socks5.Credentials{Username: "synthetic", Password: password}
	}
	var reader io.Reader = c
	if i.Kind == "http" {
		r, e := httpproxy.Connect(c, target, pair)
		if e != nil {
			t.Fatal("HTTP CONNECT", e)
		}
		reader = r
	} else {
		if _, e = socks5.ClientHandshake(c, socks5.Connect, target, pair); e != nil {
			t.Fatal("SOCKS CONNECT", e)
		}
	}
	payload := []byte("Phase20 actual payload")
	if e = socks5.WriteFull(c, payload); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, len(payload))
	if _, e = io.ReadFull(reader, b); e != nil || !bytes.Equal(b, payload) {
		t.Fatal("payload integrity", e)
	}
}
func phase20LocalUDP(t *testing.T, i client.LocalInbound, target access.Endpoint) {
	t.Helper()
	control, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", i.Listen.Port), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(3 * time.Second))
	var pair *socks5.Credentials
	if i.Auth {
		pair = &socks5.Credentials{Username: "synthetic", Password: "fixture"}
	}
	bind, e := socks5.ClientHandshake(control, socks5.UDPAssociate, access.Endpoint{Host: "0.0.0.0"}, pair)
	if e != nil {
		t.Fatal(e)
	}
	udp, e := net.DialTimeout("udp", net.JoinHostPort(bind.Host, fmt.Sprint(bind.Port)), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(3 * time.Second))
	frame, e := socks5.EncodePacket(target, []byte("Phase20 UDP payload"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = udp.Write(frame); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 2048)
	n, e := udp.Read(b)
	if e != nil {
		t.Fatal("UDP response", e)
	}
	dst, p, e := socks5.ParsePacket(b[:n])
	if e != nil || dst != target || string(p) != "Phase20 UDP payload" {
		t.Fatal("UDP payload integrity", e)
	}
}

type phase20Resources struct{ Goroutines, FDs, Listeners, Sessions, UDPWorkers int }

func phase20Sample(s *application.Service) phase20Resources {
	r := phase20Resources{Goroutines: runtime.NumGoroutine()}
	fd, e := os.ReadDir("/proc/self/fd")
	if e == nil {
		r.FDs = len(fd)
	}
	state, e := s.ClientStatus(context.Background())
	if e == nil {
		r.Sessions = len(state.Sessions)
		if state.Health == "healthy" {
			r.Listeners = len(state.LocalStats)
		}
	}
	stack := make([]byte, 1<<20)
	n := runtime.Stack(stack, true)
	r.UDPWorkers = bytes.Count(stack[:n], []byte("proxy_outbound.go")) + bytes.Count(stack[:n], []byte("clientruntime.(*Manager).serveUDP.func"))
	return r
}
func TestPhase20ProxyLifetimeAuthRotation25(t *testing.T) {
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	enableProxyInterfaces(t, s)
	echo := phase20Echo(t)
	var listeners []client.LocalInbound
	var bindings []identity.ID
	for _, kind := range []string{"socks5", "http", "mixed"} {
		i, b := createProxyListener(t, s, kind, true)
		listeners = append(listeners, i)
		bindings = append(bindings, b)
	}
	clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "stop"})
	start := phase20Sample(s)
	peak := start
	for cycle := range 26 {
		clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "start"})
		for j, i := range listeners {
			for range 8 {
				phase20Stream(t, i, echo, "fixture")
			}
			clientApply(t, s, application.ClientMutation{Resource: "local-binding", Action: "rotate", ID: bindings[j], Credential: proxyAuthInput("rotated-fixture")})
			phase20Stream(t, i, echo, "rotated-fixture")
			c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", i.Listen.Port), time.Second)
			if e != nil {
				t.Fatal(e)
			}
			_ = c.SetDeadline(time.Now().Add(time.Second))
			pair := &socks5.Credentials{Username: "synthetic", Password: "wrong-fixture"}
			if i.Kind == "http" {
				_, e = httpproxy.Connect(c, echo, pair)
			} else {
				_, e = socks5.ClientHandshake(c, socks5.Connect, echo, pair)
			}
			_ = c.Close()
			if e == nil {
				t.Fatal("wrong auth accepted")
			}
			clientApply(t, s, application.ClientMutation{Resource: "local-binding", Action: "rotate", ID: bindings[j], Credential: proxyAuthInput("fixture")})
		}
		current := phase20Sample(s)
		peak.Goroutines = max(peak.Goroutines, current.Goroutines)
		peak.FDs = max(peak.FDs, current.FDs)
		peak.Listeners = max(peak.Listeners, current.Listeners)
		peak.Sessions = max(peak.Sessions, current.Sessions)
		clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "stop"})
		wait, cancel := context.WithTimeout(ctx, 3*time.Second)
		if e := s.WaitClientIdle(wait); e != nil {
			t.Fatal(e)
		}
		cancel()
		end := phase20Sample(s)
		if cycle == 0 {
			t.Logf("warm-up start=%+v stopped=%+v", start, end)
			fds, _ := os.ReadDir("/proc/self/fd")
			for _, fd := range fds {
				target, _ := os.Readlink("/proc/self/fd/" + fd.Name())
				t.Logf("warm-up fd=%s target=%s", fd.Name(), target)
			}
			start = end
			peak = end
			continue
		}
		if end.FDs != start.FDs || end.Sessions != 0 || end.UDPWorkers != 0 {
			t.Fatalf("resource residue start=%+v end=%+v", start, end)
		}
		t.Logf("cycle=%d resources=%+v", cycle, end)
	}
	end := phase20Sample(s)
	if end.Goroutines > start.Goroutines+1 {
		t.Fatalf("goroutine residue start=%+v end=%+v", start, end)
	}
	t.Logf("x25 TCP/auth churn=675 valid plus 75 invalid rotations=150 start=%+v peak=%+v end=%+v", start, peak, end)
	state, e := s.ClientStatus(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if len(state.Accounts) != 3 {
		t.Fatal("account attribution missing")
	}
	for _, a := range state.Accounts {
		if a.Stats.Upload == 0 || a.Stats.Download == 0 || a.Stats.Active != 0 {
			t.Fatal("account byte attribution")
		}
	}
	raw, _ := json.Marshal(state)
	if bytes.Contains(raw, []byte("rotated-fixture")) || bytes.Contains(raw, []byte(`"password"`)) {
		t.Fatal("status secret leak")
	}
}
func TestPhase20CurlInboundInterop(t *testing.T) {
	if os.Getenv("SPLICORE_P20_CURL") == "" {
		t.Skip("mature curl matrix enabled by local evidence runner")
	}
	if _, e := exec.LookPath("curl"); e != nil {
		t.Fatal(e)
	}
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	enableProxyInterfaces(t, s)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Proxy-Connection") != "" {
			t.Error("origin received proxy credential")
		}
		_, _ = io.WriteString(w, "Phase20 mature client payload")
	}))
	defer origin.Close()
	for _, kind := range []string{"socks5", "http", "mixed"} {
		for _, auth := range []bool{false, true} {
			i, _ := createProxyListener(t, s, kind, auth)
			modes := []string{"socks5h"}
			if kind == "http" {
				modes = []string{"http"}
			}
			if kind == "mixed" {
				modes = []string{"socks5h", "http"}
			}
			for _, mode := range modes {
				for _, tunnel := range []bool{false, true} {
					if tunnel && mode != "http" {
						continue
					}
					args := []string{"--silent", "--show-error", "--fail", "--max-time", "5", "--noproxy", "", "--proxy", fmt.Sprintf("%s://127.0.0.1:%d", mode, i.Listen.Port)}
					if auth {
						args = append(args, "--proxy-user", "synthetic:fixture")
					}
					if tunnel {
						args = append(args, "--proxytunnel")
					}
					args = append(args, origin.URL)
					b, e := exec.Command("curl", args...).CombinedOutput()
					if e != nil || string(b) != "Phase20 mature client payload" {
						t.Fatal("curl local payload", kind, mode, auth, tunnel, e)
					}
					t.Logf("curl kind=%s mode=%s auth=%t CONNECT=%t payload PASS origin Proxy-Authorization absent", kind, mode, auth, tunnel)
				}
			}
		}
	}
}
func TestPhase20ProxyManagementImportExportProvider(t *testing.T) {
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	enableProxyInterfaces(t, s)
	for _, scheme := range []string{"socks5h", "http"} {
		c, e := nodeimport.ParseURI(scheme + "://synthetic:fixture@127.0.0.1:1#managed-proxy")
		if e != nil {
			t.Fatal(e)
		}
		created := clientApply(t, s, application.ClientMutation{Resource: "node", Action: "create", Node: &c.Node, Credential: &application.CredentialInput{Kind: c.Credential.Kind, Value: c.Credential.Value}})
		for _, format := range []string{"canonical", "uri", "mihomo", "sing-box"} {
			version := ""
			if format == "mihomo" {
				version = "1.19.32"
			}
			if format == "sing-box" {
				version = "1.14.2"
			}
			x, e := s.ExportNodes(context.Background(), application.NodeExportRequest{IDs: []identity.ID{created.ID}, Format: format, ClientVersion: version, RevealSecrets: true})
			if e != nil {
				t.Fatal("explicit proxy export", format, e)
			}
			r, e := nodeimport.Parse(format, []byte(x.Content))
			if e != nil || len(r.Candidates) != 1 || len(r.Issues) != 0 {
				t.Fatal("roundtrip", format, e, r.Issues)
			}
			if !strings.Contains(x.Content, "fixture") {
				t.Fatal("explicit export omitted secret")
			}
		}
	}
	n := client.RemoteNode{Name: "bad HTTP UDP", Protocol: proxy.Key("http"), Endpoint: access.Endpoint{Host: "127.0.0.1", Port: 1}, Transport: client.Transport{Kind: "tcp"}, Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: []byte(`{"auth":false,"udp":true}`)}}
	raw, _ := json.Marshal(application.ClientMutation{Resource: "node", Action: "create", Node: &n, Credential: &application.CredentialInput{Kind: access.Password, Value: proxy.NoAuth}})
	if s.ValidateClient(context.Background(), raw) == nil {
		t.Fatal("HTTP UDP configuration accepted")
	}
}
