package streamtransport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
	"unicode"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

func fixTLS(t *testing.T, name string) (*tls.Config, *tls.Config) {
	t.Helper()
	m := testkit.TLSForName(t, name)
	cert, err := os.ReadFile(m.CertificateFile)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(m.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	p, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(m.CACertificate)) {
		t.Fatal("fixture CA")
	}
	return &tls.Config{Certificates: []tls.Certificate{p}, MinVersion: tls.VersionTLS12}, &tls.Config{ServerName: name, RootCAs: pool, MinVersion: tls.VersionTLS12}
}

func TestGRPCIndependentIdentities(t *testing.T) {
	for _, row := range []struct{ name, dialHost, sni, authority, certName string }{
		{"A-equal", "host-a.synthetic.test", "host-a.synthetic.test", "host-a.synthetic.test", "host-a.synthetic.test"},
		{"B-ip", "127.0.0.1", "name-a.synthetic.test", "name-a.synthetic.test", "name-a.synthetic.test"},
		{"C-all-distinct", "127.0.0.1", "sni.synthetic.test", "authority.synthetic.test", "sni.synthetic.test"},
		{"C-authority-port", "127.0.0.1", "sni.synthetic.test", "sni.synthetic.test:443", "sni.synthetic.test"},
		{"D-host-distinct", "host-a.synthetic.test", "name-b.synthetic.test", "name-c.synthetic.test", "name-b.synthetic.test"},
		{"D-no-authority", "127.0.0.1", "name-a.synthetic.test", "", "name-a.synthetic.test"},
		{"E-no-sni", "127.0.0.1", "", "name-a.synthetic.test:443", "name-a.synthetic.test"},
		{"F-defaults", "host-a.synthetic.test", "", "", "host-a.synthetic.test"},
	} {
		t.Run(row.name, func(t *testing.T) {
			serverTLS, clientTLS := fixTLS(t, row.certName)
			clientTLS.ServerName = row.sni
			sni := make(chan string, 4)
			serverTLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) { sni <- hello.ServerName; return nil, nil }
			auth := make(chan string, 4)
			gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig(serverTLS, "grpc"))), grpc.ForceServerCodec(hunkCodec{}))
			gs.RegisterService(&grpc.ServiceDesc{ServiceName: "Review", HandlerType: (*any)(nil), Streams: []grpc.StreamDesc{{StreamName: "Tun", ClientStreams: true, ServerStreams: true, Handler: func(_ any, stream grpc.ServerStream) error {
				md, _ := metadata.FromIncomingContext(stream.Context())
				values := md.Get(":authority")
				if len(values) == 1 {
					auth <- values[0]
				} else {
					auth <- "INVALID"
				}
				for {
					var h hunk
					if err := stream.RecvMsg(&h); err != nil {
						return err
					}
					if err := stream.SendMsg(&h); err != nil {
						return err
					}
				}
			}}}}, nil)
			raw, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { _ = gs.Serve(raw); close(done) }()
			defer func() { gs.Stop(); raw.Close(); <-done }()
			_, port, _ := net.SplitHostPort(raw.Addr().String())
			endpoint := net.JoinHostPort(row.dialHost, port)
			calls := make(chan string, 4)
			approved, _ := underlay.New().New(underlay.Scope{Purpose: underlay.ProxyUnderlay})
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				calls <- address
				// Owned synthetic DNS mapping; the transport must pass the original endpoint.
				return approved.DialContext(ctx, network, raw.Addr().String())
			}
			c := cfg.Config{Kind: "grpc", Host: row.authority, ServiceName: "Review"}
			if err = c.ValidatePair("vmess", "tls"); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := Dial(ctx, dial, endpoint, c, clientTLS)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			payload := bytes.Repeat([]byte("independent-identities"), 6000)
			write := make(chan error, 1)
			go func() { _, err := conn.Write(payload); write <- err }()
			got := make([]byte, len(payload))
			if _, err = io.ReadFull(conn, got); err != nil {
				t.Fatal(err)
			}
			if err = <-write; err != nil || !bytes.Equal(got, payload) {
				t.Fatal("payload mismatch", err)
			}
			wantAuthority := row.authority
			if wantAuthority == "" {
				wantAuthority = row.sni
			}
			if wantAuthority == "" {
				wantAuthority = endpoint
			}
			capturedSNI, capturedAuthority, dialTarget := <-sni, <-auth, <-calls
			if capturedSNI != row.certName || capturedAuthority != wantAuthority || dialTarget != endpoint || clientTLS.InsecureSkipVerify {
				t.Fatal(capturedSNI, capturedAuthority, dialTarget)
			}
			b, _ := json.Marshal(map[string]any{"case": row.name, "endpoint": endpoint, "dial_target": dialTarget, "physical_connection": raw.Addr().String(), "tls_server_name": row.sni, "observed_sni": capturedSNI, "configured_authority": row.authority, "observed_authority": capturedAuthority, "expected_authority": wantAuthority, "verification": true, "payload_bytes": len(payload), "reply": "PASS"})
			t.Log("IDENTITY_JSON " + string(b))
		})
	}
}

func TestGRPCIndependentTLSFailures(t *testing.T) {
	for _, mode := range []string{"wrong-name", "untrusted-ca"} {
		t.Run(mode, func(t *testing.T) {
			st, ct := fixTLS(t, "name-a.synthetic.test")
			if mode == "wrong-name" {
				ct.ServerName = "wrong.synthetic.test"
			} else {
				ct.RootCAs = x509.NewCertPool()
			}
			raw, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			l, err := WrapListener(raw, cfg.Config{Kind: "grpc", Host: "authority.synthetic.test"}, st)
			if err != nil {
				raw.Close()
				t.Fatal(err)
			}
			defer l.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			d, _ := underlay.New().New(underlay.Scope{Purpose: underlay.ProxyUnderlay})
			c, err := Dial(ctx, d.DialContext, raw.Addr().String(), cfg.Config{Kind: "grpc", Host: "authority.synthetic.test"}, ct)
			if err == nil {
				c.Close()
				t.Fatal("invalid TLS accepted")
			}
			t.Log("TLS verification rejected", mode, err)
		})
	}
	for _, protocol := range []string{"ss", "snell", "hy2", "tuic", "mieru"} {
		if (cfg.Config{Kind: "grpc"}).ValidatePair(protocol, "tls") == nil {
			t.Fatal("unsupported protocol", protocol)
		}
	}
	if (cfg.Config{Kind: "grpc"}).ValidatePair("vless", "reality") == nil {
		t.Fatal("REALITY boundary")
	}
}

func TestGRPCTLSCredentialsClone(t *testing.T) {
	_, ct := fixTLS(t, "name-a.synthetic.test")
	c := &grpcTLSCredentials{base: credentials.NewTLS(ct), serverName: ct.ServerName}
	clone := c.Clone().(*grpcTLSCredentials)
	if err := clone.OverrideServerName("name-b.synthetic.test"); err != nil {
		t.Fatal(err)
	}
	if c.serverName != ct.ServerName || clone.serverName != "name-b.synthetic.test" || clone.base.Info().ServerName != clone.serverName || clone.Info().ServerName != "" {
		t.Fatal("clone/override identity")
	}
}

func TestHTTPUpgrade101Framing(t *testing.T) {
	for _, row := range []struct {
		name, status, headers string
		valid                 bool
	}{
		{"valid", "HTTP/1.1 101 Switching Protocols", "", true},
		{"cl-zero", "HTTP/1.1 101 Switching Protocols", "Content-Length: 0\r\n", true},
		{"cl-one", "HTTP/1.1 101 Switching Protocols", "Content-Length: 1\r\n", false},
		{"cl-original-two", "HTTP/1.1 101 Switching Protocols", "Content-Length: 2\r\n", false},
		{"cl-hundred", "HTTP/1.1 101 Switching Protocols", "Content-Length: 100\r\n", false},
		{"conflicting-cl", "HTTP/1.1 101 Switching Protocols", "Content-Length: 0\r\nContent-Length: 1\r\n", false},
		{"malformed-cl", "HTTP/1.1 101 Switching Protocols", "Content-Length: invalid\r\n", false},
		{"negative-cl", "HTTP/1.1 101 Switching Protocols", "Content-Length: -1\r\n", false},
		{"te-chunked", "HTTP/1.1 101 Switching Protocols", "Transfer-Encoding: chunked\r\n", false},
		{"te-empty", "HTTP/1.1 101 Switching Protocols", "Transfer-Encoding:\r\n", false},
		{"te-identity", "HTTP/1.1 101 Switching Protocols", "Transfer-Encoding: identity\r\n", false},
		{"cl-te", "HTTP/1.1 101 Switching Protocols", "Content-Length: 2\r\nTransfer-Encoding: chunked\r\n", false},
		{"200", "HTTP/1.1 200 OK", "Content-Length: 0\r\n", false},
		{"204", "HTTP/1.1 204 No Content", "", false},
		{"302", "HTTP/1.1 302 Found", "Content-Length: 0\r\n", false},
		{"malformed-status", "HTTP/1.1 xyz Switching Protocols", "", false},
		{"wrong-version", "HTTP/1.0 101 Switching Protocols", "", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer b.Close()
			done := make(chan error, 1)
			go func() {
				defer b.Close()
				b.SetDeadline(time.Now().Add(3 * time.Second))
				_, err := http.ReadRequest(bufio.NewReader(b))
				if err == nil {
					_, err = io.WriteString(b, row.status+"\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"+row.headers+"\r\nfirstsecond")
				}
				done <- err
			}()
			conn, err := Dial(context.Background(), func(context.Context, string, string) (net.Conn, error) { return a, nil }, "127.0.0.1:12345", cfg.Config{Kind: "httpupgrade"}, nil)
			if (err == nil) != row.valid {
				if conn != nil {
					conn.Close()
				}
				t.Fatal("unexpected acceptance", err)
			}
			if row.valid {
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				got := make([]byte, 11)
				if _, err = io.ReadFull(conn, got); err != nil || string(got) != "firstsecond" {
					t.Fatal("buffer lost", string(got), err)
				}
				conn.Close()
			}
			<-done
			t.Logf("FRAMING_JSON {\"case\":%q,\"accepted\":%t,\"expected\":%t}", row.name, err == nil, row.valid)
		})
	}
}

// Fuzz only Splicore's post-parse semantic validator, not net/http's parser.
func FuzzHTTPUpgradeResponseSemantics(f *testing.F) {
	f.Add("0", "", uint16(101))
	f.Add("2", "chunked", uint16(101))
	f.Fuzz(func(t *testing.T, cl, te string, status uint16) {
		if len(cl)+len(te) > 4096 {
			return
		}
		r := &http.Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: int(status), Header: http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Content-Length": {cl}}}
		if te != "" {
			r.Header["Transfer-Encoding"] = []string{te}
		}
		if validUpgradeResponse(r) && (status != 101 || te != "") {
			t.Fatal("unsafe semantic acceptance")
		}
		if validUpgradeResponse(r) {
			for _, ch := range cl {
				if ch != '0' && !unicode.IsSpace(ch) {
					t.Fatal("nonzero/malformed framing accepted")
				}
			}
		}
	})
}
