package backend

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/testkit"
)

type h2SetupObservedConn struct {
	net.Conn
	applicationWrite, closed chan struct{}
	writeOnce, closeOnce     sync.Once
	mu                       sync.Mutex
	deadlines                []time.Time
}

func (c *h2SetupObservedConn) Write(p []byte) (int, error) {
	// TLS 1.2 application data is distinct from all handshake records.
	if len(p) > 0 && p[0] == 23 && c.applicationWrite != nil {
		c.writeOnce.Do(func() { close(c.applicationWrite) })
	}
	return c.Conn.Write(p)
}
func (c *h2SetupObservedConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}
func (c *h2SetupObservedConn) SetDeadline(d time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, d)
	c.mu.Unlock()
	return c.Conn.SetDeadline(d)
}

func TestNaiveH2InitializationCancellation(t *testing.T) {
	for _, action := range []string{"caller-cancel", "setup-timeout", "client-close"} {
		t.Run(action, func(t *testing.T) {
			settings := testkit.TLS(t)
			cert, err := tls.LoadX509KeyPair(settings.CertificateFile, settings.PrivateKeyFile)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM([]byte(settings.CACertificate)) {
				t.Fatal("CA")
			}
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			observed := &h2SetupObservedConn{Conn: left, applicationWrite: make(chan struct{}), closed: make(chan struct{})}
			handshake, peerDone := make(chan error, 1), make(chan struct{})
			go func() {
				defer close(peerDone)
				peer := tls.Server(right, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
				handshake <- peer.Handshake()
				// Deliberately never read the H2 preface. net.Pipe has no
				// write buffer, so the first application record must block.
				<-observed.closed
			}()
			client, err := NewClient(ClientConfig{Mode: "https", Proxy: "controlled:443", TLS: &tls.Config{ServerName: settings.ServerName, RootCAs: roots, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}, ConnectTimeout: 2 * time.Second,
				DialTCP: func(context.Context, string, string) (net.Conn, error) { return observed, nil }})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			opened := make(chan error, 1)
			go func() {
				conn, err := client.Open(ctx, "127.0.0.1:80")
				if conn != nil {
					conn.Close()
				}
				opened <- err
			}()
			halfCloseResult(t, handshake)
			halfCloseWait(t, observed.applicationWrite)
			select {
			case err := <-opened:
				t.Fatal("initial write was not blocked", err)
			default:
			}
			closed := make(chan error, 1)
			switch action {
			case "caller-cancel":
				cancel()
			case "client-close":
				go func() { closed <- client.Close() }()
			}
			select {
			case err := <-opened:
				if err == nil {
					t.Fatal("blocked setup succeeded")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("initial H2 write ignored cancellation")
			}
			if action == "client-close" {
				halfCloseResult(t, closed)
			}
			halfCloseWait(t, observed.closed)
			halfCloseWait(t, peerDone)
			client.mu.Lock()
			owners := len(client.capacity) + len(client.retired)
			for _, slot := range client.slots {
				if slot != nil {
					owners++
				}
			}
			client.mu.Unlock()
			if owners != 0 {
				t.Fatal("failed initialization retained owners", owners)
			}
			t.Log("TLS handshake completed; initial H2 application write blocked; setup canceled and joined")
		})
	}
}

func TestNaiveH2InitializationDeadlineCleared(t *testing.T) {
	proxy, tc, _ := startTestServer(t, "https")
	var observed *h2SetupObservedConn
	var setup context.Context
	client := newTestClient(t, "https", proxy, tc, func(c *ClientConfig) {
		c.DialTCP = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			setup = ctx
			observed = &h2SetupObservedConn{Conn: conn, closed: make(chan struct{})}
			return observed, nil
		}
	}, nil)
	conn, err := client.Open(context.Background(), echoTarget(t, "tcp", "127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	halfCloseWait(t, setup.Done())
	observed.mu.Lock()
	deadlines := append([]time.Time(nil), observed.deadlines...)
	observed.mu.Unlock()
	if len(deadlines) != 2 || deadlines[0].IsZero() || !deadlines[1].IsZero() {
		t.Fatal("setup deadline not cleared", deadlines)
	}
	select {
	case <-observed.closed:
		t.Fatal("completed setup cancellation closed pooled connection")
	default:
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("still alive")); err != nil {
		t.Fatal(err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil || string(got) != "still alive" {
		t.Fatal("connection inherited setup lifetime", string(got), err)
	}
}
