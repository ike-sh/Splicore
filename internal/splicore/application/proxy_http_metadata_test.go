package application_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/nodeimport"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
)

const fixSecretMarker = "phase20-proxy-secret-marker"

type fixOriginCapture struct {
	Header, Trailer http.Header
	Declarations    []string
	Body            []byte
	Raw             string
	BodyError       string
}

func fixRecord(t *testing.T, name string, value any) {
	t.Helper()
	if root := os.Getenv("SPLICORE_P20_FIX_EVIDENCE"); root != "" {
		b, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(root, name), append(b, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func fixService(t *testing.T) *application.Service {
	t.Helper()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, registry.NativeCore)
	enableProxyInterfaces(t, s)
	t.Cleanup(func() { stop(t, s, store) })
	return s
}

// Capture actual origin wire bytes, declaration keys before EOF, and final
// trailers after EOF. This listener is local and each worker is joined.
func fixOrigin(t *testing.T) (net.Listener, <-chan fixOriginCapture) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rows := make(chan fixOriginCapture, 512)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				var raw bytes.Buffer
				r, err := http.ReadRequest(bufio.NewReader(io.TeeReader(c, &raw)))
				if err != nil {
					rows <- fixOriginCapture{Raw: raw.String(), BodyError: err.Error()}
					return
				}
				row := fixOriginCapture{Header: r.Header.Clone()}
				for name := range r.Trailer {
					row.Declarations = append(row.Declarations, name)
				}
				row.Body, err = io.ReadAll(r.Body)
				if err != nil {
					row.BodyError = err.Error()
				}
				row.Trailer = r.Trailer.Clone()
				row.Raw = raw.String()
				r.Body.Close()
				rows <- row
				io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nfix-response")
			}()
		}
	}()
	t.Cleanup(func() { l.Close(); wg.Wait() })
	return l, rows
}

func fixDial(t *testing.T, i client.LocalInbound) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", i.Listen.Port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(8 * time.Second))
	return c
}

func fixResponse(t *testing.T, c net.Conn) *http.Response {
	t.Helper()
	r, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "POST"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode == 200 && string(b) != "fix-response" {
		t.Fatalf("response integrity %q", b)
	}
	return r
}

func fixCapture(t *testing.T, rows <-chan fixOriginCapture) fixOriginCapture {
	t.Helper()
	select {
	case row := <-rows:
		return row
	case <-time.After(6 * time.Second):
		t.Fatal("origin not observed")
		return fixOriginCapture{}
	}
}

func fixAssertProtected(t *testing.T, row fixOriginCapture, body []byte, markers ...string) {
	t.Helper()
	if row.BodyError != "" || !bytes.Equal(row.Body, body) {
		t.Fatal("origin body integrity", row.BodyError, len(row.Body), len(body))
	}
	for _, name := range []string{"Proxy-Authorization", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authentication-Info", "Connection", "Keep-Alive", "TE", "Trailer", "Upgrade", "X-Hop"} {
		if row.Header.Get(name) != "" && name != "Connection" {
			t.Fatalf("origin header %s", name)
		}
		if _, ok := row.Trailer[name]; ok {
			t.Fatalf("origin trailer %s", name)
		}
		for _, decl := range row.Declarations {
			if strings.EqualFold(decl, name) {
				t.Fatalf("origin declaration %s", name)
			}
		}
	}
	for _, marker := range markers {
		if strings.Contains(row.Raw, marker) {
			t.Fatal("credential marker in origin wire")
		}
	}
}

func TestPhase20HTTPMetadataSecurityMatrix(t *testing.T) {
	s := fixService(t)
	origin, rows := fixOrigin(t)
	marker := "Basic " + fixSecretMarker
	type scenario struct {
		name, header, declaration, final string
		body                             []byte
		fragment                         bool
		safe                             bool
	}
	cases := []scenario{
		{"A-header", marker, "", "", nil, false, false},
		{"B-trailer", "", "Trailer: Proxy-Authorization\r\n", "Proxy-Authorization: " + marker + "\r\n", []byte("small"), false, false},
		{"C-both", marker, "Trailer: Proxy-Authorization\r\n", "Proxy-Authorization: different-" + marker + "\r\n", []byte("multi-chunk-body"), false, false},
		{"D-mixed-case", "", "Trailer: pRoXy-AuThOrIzAtIoN\r\n", "pRoXy-AuThOrIzAtIoN: " + marker + "\r\n", []byte("case"), false, false},
		{"D-uppercase", "", "Trailer: PROXY-AUTHORIZATION\r\n", "PROXY-AUTHORIZATION: " + marker + "\r\n", []byte("upper"), false, false},
		{"E-safe-duplicates", marker, "Trailer: X-Splicore-Test-Checksum, Proxy-Authorization\r\nTrailer: proxy-authorization, X-Splicore-Test-Checksum\r\n", "Proxy-Authorization: " + marker + "\r\nX-Splicore-Test-Checksum: safe-value\r\n", []byte("safe"), false, true},
		{"F-large-stream", marker, "Trailer: Proxy-Authorization, X-Splicore-Test-Checksum\r\n", "Proxy-Authorization: " + marker + "\r\nX-Splicore-Test-Checksum: safe-value\r\n", bytes.Repeat([]byte("large-stream-data"), 1<<17), false, true},
		{"G-fragmented", "", "Trailer: Proxy-Authorization, X-Splicore-Test-Checksum\r\n", "Proxy-Authorization: " + marker + "\r\nX-Splicore-Test-Checksum: safe-value\r\n", []byte("fragmented-multiple-chunks"), true, true},
		{"hop-fields", "", "Trailer: Proxy-Authorization, Proxy-Connection, Proxy-Authenticate, Proxy-Authentication-Info, Connection, Keep-Alive, TE, Upgrade, X-Hop, X-Splicore-Test-Checksum\r\n", "Proxy-Authorization: " + marker + "\r\nProxy-Connection: " + marker + "\r\nProxy-Authenticate: " + marker + "\r\nProxy-Authentication-Info: " + marker + "\r\nConnection: ignored\r\nKeep-Alive: hop\r\nTE: hop\r\nUpgrade: hop\r\nX-Hop: hop\r\nX-Splicore-Test-Checksum: safe-value\r\n", []byte("hop"), false, true},
		{"undeclared-credential", "", "Trailer: X-Splicore-Test-Checksum\r\n", "Proxy-Authorization: " + marker + "\r\nX-Splicore-Test-Checksum: safe-value\r\n", []byte("undeclared"), false, true},
	}
	results := []map[string]any{}
	for _, kind := range []string{"http", "mixed"} {
		i, _ := createProxyListener(t, s, kind, false)
		for _, tc := range cases {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				c := fixDial(t, i)
				defer c.Close()
				head := fmt.Sprintf("POST http://%s/upload HTTP/1.1\r\nHost: %s\r\nConnection: X-Hop\r\nX-Hop: header-hop\r\nX-End-To-End: preserved\r\n", origin.Addr(), origin.Addr())
				if tc.header != "" {
					head += "Proxy-Authorization: " + tc.header + "\r\n"
				}
				var wire bytes.Buffer
				wire.WriteString(head)
				if tc.declaration == "" {
					fmt.Fprintf(&wire, "Content-Length: %d\r\n\r\n", len(tc.body))
					wire.Write(tc.body)
				} else {
					wire.WriteString("Transfer-Encoding: chunked\r\n" + tc.declaration + "\r\n")
					for p := tc.body; len(p) > 0; {
						n := min(len(p), 32768)
						if tc.fragment {
							n = min(n, 3)
						}
						fmt.Fprintf(&wire, "%x\r\n", n)
						wire.Write(p[:n])
						wire.WriteString("\r\n")
						p = p[n:]
					}
					wire.WriteString("0\r\n" + tc.final + "\r\n")
				}
				if tc.fragment {
					for _, b := range wire.Bytes() {
						if _, err := c.Write([]byte{b}); err != nil {
							t.Fatal(err)
						}
					}
				} else if _, err := c.Write(wire.Bytes()); err != nil {
					t.Fatal(err)
				}
				r := fixResponse(t, c)
				if r.StatusCode != 200 || !r.Close {
					t.Fatal("status/close contract", r.StatusCode, r.Close)
				}
				row := fixCapture(t, rows)
				fixAssertProtected(t, row, tc.body, fixSecretMarker)
				if row.Header.Get("X-End-To-End") != "preserved" {
					t.Fatal("end-to-end header")
				}
				if tc.safe && (len(row.Trailer.Values("X-Splicore-Test-Checksum")) != 1 || row.Trailer.Get("X-Splicore-Test-Checksum") != "safe-value") {
					t.Fatal("safe trailer lost")
				}
				results = append(results, map[string]any{"path": kind, "case": tc.name, "status": r.StatusCode, "body_bytes": len(row.Body), "body_exact": true, "origin_header_credential_count": 0, "origin_trailer_credential_count": 0, "credential_byte_occurrences": 0, "safe_preserved": tc.safe, "declarations": row.Declarations, "trailers": row.Trailer})
			})
		}
	}
	fixRecord(t, "header-trailer-security-matrix.json", results)
}

func TestPhase20HTTPMetadataStreamingBeforeEOF(t *testing.T) {
	s := fixService(t)
	i, _ := createProxyListener(t, s, "http", false)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	first := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		r, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			done <- err
			return
		}
		p := make([]byte, 1024)
		_, err = io.ReadFull(r.Body, p)
		if err != nil {
			done <- err
			return
		}
		close(first)
		rest, err := io.ReadAll(r.Body)
		if err == nil && (len(rest) != (2<<20) || r.Trailer.Get("Proxy-Authorization") != "" || r.Trailer.Get("X-Safe") != "exact") {
			err = fmt.Errorf("stream/trailer integrity")
		}
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nfix-response")
		done <- err
	}()
	c := fixDial(t, i)
	defer c.Close()
	fmt.Fprintf(c, "POST http://%s/ HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nTrailer: Proxy-Authorization, X-Safe\r\n\r\n400\r\n%s\r\n", l.Addr(), l.Addr(), strings.Repeat("a", 1024))
	select {
	case <-first:
	case <-time.After(2 * time.Second):
		t.Fatal("origin did not receive body before client EOF")
	}
	payload := strings.Repeat("b", 2<<20)
	fmt.Fprintf(c, "%x\r\n%s\r\n0\r\nProxy-Authorization: %s\r\nX-Safe: exact\r\n\r\n", len(payload), payload, fixSecretMarker)
	if r := fixResponse(t, c); r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	fixRecord(t, "body-streaming-regression.json", map[string]any{"origin_received_before_client_EOF": true, "body_bytes": 1024 + (2 << 20), "body_exact": true, "whole_body_buffering": false, "forbidden_trailer_absent": true, "safe_trailer": "exact"})
}

func TestPhase20HTTPMetadataAuthenticationAndIsolation(t *testing.T) {
	s := fixService(t)
	origin, rows := fixOrigin(t)
	i, _ := createProxyListener(t, s, "http", true)
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte("synthetic:fixture"))
	for _, header := range []string{"", "Basic invalid", auth} {
		c := fixDial(t, i)
		h := ""
		if header != "" {
			h = "Proxy-Authorization: " + header + "\r\n"
		}
		fmt.Fprintf(c, "POST http://%s/ HTTP/1.1\r\nHost: %s\r\n%sTransfer-Encoding: chunked\r\nTrailer: Proxy-Authorization\r\n\r\n1\r\na\r\n0\r\nProxy-Authorization: %s\r\n\r\n", origin.Addr(), origin.Addr(), h, auth)
		r := fixResponse(t, c)
		c.Close()
		if header == auth {
			if r.StatusCode != 200 {
				t.Fatal(r.StatusCode)
			}
			fixAssertProtected(t, fixCapture(t, rows), []byte("a"), auth)
		} else if r.StatusCode != 407 {
			t.Fatal("late auth bypass", r.StatusCode)
		}
	}
	select {
	case <-rows:
		t.Fatal("407 reached origin")
	default:
	}
	for n := range 60 {
		c := fixDial(t, i)
		payload := fmt.Sprintf("request-%d", n)
		trail := ""
		if n%3 == 0 {
			trail = "Proxy-Authorization: " + fixSecretMarker + "\r\n"
		}
		if n%3 == 1 {
			trail = "X-Safe: isolated-value\r\n"
		}
		fmt.Fprintf(c, "POST http://%s/ HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\nTransfer-Encoding: chunked\r\nTrailer: Proxy-Authorization, X-Safe\r\n\r\n%x\r\n%s\r\n0\r\n%s\r\n", origin.Addr(), origin.Addr(), auth, len(payload), payload, trail)
		r := fixResponse(t, c)
		if r.StatusCode != 200 || !r.Close {
			t.Fatal("close contract")
		}
		c.Close()
		row := fixCapture(t, rows)
		fixAssertProtected(t, row, []byte(payload), auth, fixSecretMarker)
		want := ""
		if n%3 == 1 {
			want = "isolated-value"
		}
		if row.Trailer.Get("X-Safe") != want {
			t.Fatal("cross-request trailer contamination")
		}
	}
	fixRecord(t, "keepalive-isolation.json", map[string]any{"result": "PASS within user-approved Connection: close contract", "same_connection_second_request": "UNSUPPORTED; explicitly excluded by user", "reconnections": 60, "alternating_forbidden_safe_empty_trailers": true, "stale_metadata": 0, "late_trailer_authentication": "407; no origin connection", "normal_header_authentication": "200"})
}

func TestPhase20HTTPTwoHopCredentialBoundary(t *testing.T) {
	s := fixService(t)
	origin, rows := fixOrigin(t)
	up, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	authA := "Basic " + base64.StdEncoding.EncodeToString([]byte("synthetic:fixture"))
	authB := "Basic " + base64.StdEncoding.EncodeToString([]byte("upstream-synthetic:phase20-upstream-fixture-B"))
	observed := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		c, err := up.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		rdr := bufio.NewReader(c)
		r, err := http.ReadRequest(rdr)
		if err != nil {
			done <- err
			return
		}
		observed <- r.Header.Get("Proxy-Authorization")
		if r.Method != "CONNECT" || r.Host != origin.Addr().String() || r.Header.Get("Proxy-Authorization") != authB {
			done <- fmt.Errorf("upstream CONNECT/auth")
			return
		}
		target, err := net.DialTimeout("tcp", origin.Addr().String(), time.Second)
		if err != nil {
			done <- err
			return
		}
		defer target.Close()
		target.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		joined := make(chan struct{})
		go func() { io.Copy(target, rdr); target.(*net.TCPConn).CloseWrite(); close(joined) }()
		_, err = io.Copy(c, target)
		c.Close()
		<-joined
		done <- err
	}()
	candidate, err := nodeimport.ParseURI(fmt.Sprintf("http://upstream-synthetic:phase20-upstream-fixture-B@%s#fix-upstream", up.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	node := clientApply(t, s, application.ClientMutation{Resource: "node", Action: "create", Node: &candidate.Node, Credential: &application.CredentialInput{Kind: candidate.Credential.Kind, Value: candidate.Credential.Value}})
	outSpec := client.Outbound{Name: "fix upstream", Kind: "proxy", NodeID: &node.ID, Engine: "native"}
	out := clientApply(t, s, application.ClientMutation{Resource: "outbound", Action: "create", Outbound: &outSpec})
	i, _ := createProxyListener(t, s, "http", true)
	status, err := s.ClientStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, configured := range status.State.LocalInbounds {
		if configured.ID == i.ID {
			i = configured // Preserve the account bindings when changing selection.
		}
	}
	i.SelectedOutbound = out.ID
	clientApply(t, s, application.ClientMutation{Resource: "local-inbound", Action: "update", ID: i.ID, LocalInbound: &i})
	c := fixDial(t, i)
	defer c.Close()
	fmt.Fprintf(c, "POST http://%s/ HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\nTransfer-Encoding: chunked\r\nTrailer: Proxy-Authorization, X-Safe\r\n\r\n4\r\ndata\r\n0\r\nProxy-Authorization: %s\r\nX-Safe: two-hop-safe\r\n\r\n", origin.Addr(), origin.Addr(), authA, authA)
	if r := fixResponse(t, c); r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	c.Close()
	row := fixCapture(t, rows)
	fixAssertProtected(t, row, []byte("data"), authA, authB, "phase20-upstream-fixture-B")
	if row.Trailer.Get("X-Safe") != "two-hop-safe" {
		t.Fatal("two-hop safe trailer")
	}
	if got := <-observed; got != authB || got == authA {
		t.Fatal("credential boundary")
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	fixRecord(t, "two-hop-credential-boundary.json", map[string]any{"result": "PASS", "client_A": "Splicore only", "upstream_B": "upstream CONNECT only", "origin_A_occurrences": 0, "origin_B_occurrences": 0, "upstream_received_B": true, "upstream_received_A": false, "actual_origin_status": 200, "safe_trailer_preserved": true})
}

func TestPhase20HTTPMetadataAbnormalAndResponseTrailers(t *testing.T) {
	s := fixService(t)
	origin, rows := fixOrigin(t)
	i, _ := createProxyListener(t, s, "http", false)
	for _, ending := range []string{"2\r\na", "1\r\na\r\nZ\r\n", "1\r\na\r\n0\r\nProxy-Authorization: " + fixSecretMarker + "\r\n"} {
		c := fixDial(t, i)
		fmt.Fprintf(c, "POST http://%s/ HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nTrailer: Proxy-Authorization, X-Safe\r\n\r\n%s", origin.Addr(), origin.Addr(), ending)
		c.(*net.TCPConn).CloseWrite()
		io.Copy(io.Discard, c)
		c.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.WaitClientIdle(ctx); err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case row := <-rows:
			if strings.Contains(row.Raw, fixSecretMarker) || row.Trailer.Get("Proxy-Authorization") != "" {
				t.Fatal("abnormal leak")
			}
		default:
			goto response
		}
	}
response:
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = http.ReadRequest(bufio.NewReader(c))
		if err == nil {
			_, err = io.WriteString(c, "HTTP/1.1 200 OK\r\nConnection: X-Hop, close\r\nTransfer-Encoding: chunked\r\nTrailer: Proxy-Authenticate, X-Hop, X-Safe\r\n\r\n3\r\nabc\r\n0\r\nProxy-Authenticate: response-secret\r\nX-Hop: hop-secret\r\nX-Safe: response-safe\r\n\r\n")
		}
		done <- err
	}()
	c := fixDial(t, i)
	defer c.Close()
	fmt.Fprintf(c, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", l.Addr(), l.Addr())
	r, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil || string(b) != "abc" || r.Trailer.Get("X-Safe") != "response-safe" || len(r.Trailer) != 1 {
		t.Fatal("response trailer policy", err, r.Trailer)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	fixRecord(t, "abnormal-response-regression.json", map[string]any{"premature_close": true, "malformed_chunk": true, "incomplete_trailer": true, "credential_leaks": 0, "response_safe_preserved": true, "response_proxy_and_nominated_stripped": true})
}

func TestPhase20HTTPCurlChunkedFixInterop(t *testing.T) {
	if os.Getenv("SPLICORE_P20_CURL") == "" {
		t.Skip("local curl fixture enabled by evidence runner")
	}
	s := fixService(t)
	origin, rows := fixOrigin(t)
	i, _ := createProxyListener(t, s, "http", true)
	args := []string{"--silent", "--show-error", "--fail", "--max-time", "5", "--noproxy", "", "--proxy", fmt.Sprintf("http://127.0.0.1:%d", i.Listen.Port), "--proxy-user", "synthetic:fixture", "-H", "Transfer-Encoding: chunked", "--data-binary", "@-", "http://" + origin.Addr().String() + "/"}
	cmd := exec.Command("curl", args...)
	cmd.Stdin = strings.NewReader("curl-chunked-body")
	b, err := cmd.CombinedOutput()
	if err != nil || string(b) != "fix-response" {
		t.Fatal("curl chunked", err, string(b))
	}
	fixAssertProtected(t, fixCapture(t, rows), []byte("curl-chunked-body"), base64.StdEncoding.EncodeToString([]byte("synthetic:fixture")))
	fixRecord(t, "curl-chunked-regression.json", map[string]any{"result": "PASS", "actual_reply": "fix-response", "body_exact": true})
}

func TestPhase20HTTPMetadataCancelUpload(t *testing.T) {
	s := fixService(t)
	i, _ := createProxyListener(t, s, "http", false)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	first, done := make(chan struct{}), make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		var raw bytes.Buffer
		r, err := http.ReadRequest(bufio.NewReader(io.TeeReader(c, &raw)))
		if err != nil {
			done <- err
			return
		}
		_, err = io.ReadFull(r.Body, make([]byte, 1024))
		if err != nil {
			done <- err
			return
		}
		close(first)
		_, err = io.Copy(io.Discard, r.Body)
		if err == nil || strings.Contains(raw.String(), fixSecretMarker) || r.Trailer.Get("Proxy-Authorization") != "" {
			done <- fmt.Errorf("upload cancellation/credential boundary")
			return
		}
		done <- nil
	}()
	c := fixDial(t, i)
	defer c.Close()
	fmt.Fprintf(c, "POST http://%s/ HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nTrailer: Proxy-Authorization, X-Safe\r\n\r\n400\r\n%s\r\n", l.Addr(), l.Addr(), strings.Repeat("a", 1024))
	select {
	case <-first:
	case <-time.After(2 * time.Second):
		t.Fatal("upload not streaming")
	}
	clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "stop"})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err = s.WaitClientIdle(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	fixRecord(t, "upload-cancellation.json", map[string]any{"result": "PASS", "origin_received_partial_body": true, "parent_stop_joined": true, "credential_leaks": 0})
}

func TestPhase20HTTPMetadataLifecycleChurn(t *testing.T) {
	s := fixService(t)
	origin, rows := fixOrigin(t)
	i, _ := createProxyListener(t, s, "mixed", false)
	clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "stop"})
	baseline := phase20Sample(s)
	peak := baseline
	for cycle := range 26 {
		clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "start"})
		for range 8 {
			c := fixDial(t, i)
			fmt.Fprintf(c, "POST http://%s/ HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nTrailer: Proxy-Authorization, X-Safe\r\n\r\n1\r\na\r\n0\r\nProxy-Authorization: %s\r\nX-Safe: churn\r\n\r\n", origin.Addr(), origin.Addr(), fixSecretMarker)
			if r := fixResponse(t, c); r.StatusCode != 200 {
				t.Fatal(r.StatusCode)
			}
			c.Close()
			fixAssertProtected(t, fixCapture(t, rows), []byte("a"), fixSecretMarker)
		}
		current := phase20Sample(s)
		peak.FDs = max(peak.FDs, current.FDs)
		peak.Goroutines = max(peak.Goroutines, current.Goroutines)
		clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "stop"})
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := s.WaitClientIdle(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		end := phase20Sample(s)
		if cycle == 0 {
			baseline = end
			continue
		}
		if end.FDs != baseline.FDs || end.Sessions != 0 || end.Goroutines > baseline.Goroutines+1 {
			t.Fatalf("HTTP churn residue start=%+v end=%+v", baseline, end)
		}
	}
	fixRecord(t, "http-lifecycle-churn.json", map[string]any{"cycles": 25, "successful_streams": 200, "baseline": baseline, "peak": peak, "stopped": phase20Sample(s), "leaks": 0})
}

// A concurrent request body cannot share a trailer map with another session.
func TestPhase20HTTPMetadataConcurrent(t *testing.T) {
	s := fixService(t)
	origin, rows := fixOrigin(t)
	i, _ := createProxyListener(t, s, "mixed", false)
	var wg sync.WaitGroup
	var failures atomic.Int64
	for n := range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", i.Listen.Port), time.Second)
			if err != nil {
				failures.Add(1)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			fmt.Fprintf(c, "POST http://%s/ HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nTrailer: Proxy-Authorization, X-Safe\r\n\r\n1\r\na\r\n0\r\nProxy-Authorization: %s\r\nX-Safe: concurrent-%d\r\n\r\n", origin.Addr(), origin.Addr(), fixSecretMarker, n)
			r, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "POST"})
			if err != nil {
				failures.Add(1)
				return
			}
			b, err := io.ReadAll(r.Body)
			r.Body.Close()
			if err != nil || r.StatusCode != 200 || string(b) != "fix-response" {
				failures.Add(1)
			}
		}()
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatal("concurrent requests", failures.Load())
	}
	seen := map[string]bool{}
	for range 24 {
		row := fixCapture(t, rows)
		fixAssertProtected(t, row, []byte("a"), fixSecretMarker)
		v := row.Trailer.Get("X-Safe")
		if seen[v] || !strings.HasPrefix(v, "concurrent-") {
			t.Fatal("session contamination")
		}
		seen[v] = true
	}
}
