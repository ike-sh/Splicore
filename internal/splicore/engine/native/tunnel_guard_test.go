//go:build with_utls

package native_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/clientruntime"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/engine/native"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	vl "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func TestRealityVisionLocalTunnelGuard(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ctx = underlay.WithFactory(ctx, underlay.New())
	nameA := "www.3verge.com"
	nameB := "approved-b.test"
	nameC := "handshake-only-c.test"
	material := testkit.TLSForName(t, nameA)
	certPEM, _ := os.ReadFile(material.CertificateFile)
	keyPEM, _ := os.ReadFile(material.PrivateKeyFile)
	pair, e := tls.X509KeyPair(certPEM, keyPEM)
	clear(keyPEM)
	if e != nil {
		t.Fatal(e)
	}
	tc := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}}
	cover, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var count atomic.Int64
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			raw, e := cover.Accept()
			if e != nil {
				return
			}
			count.Add(1)
			wg.Go(func() {
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(5 * time.Second))
				c := tls.Server(raw, tc)
				io.Copy(c, c)
			})
		}
	})
	t.Cleanup(func() { cover.Close(); wg.Wait() })
	reserve, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	endpoint := guardEndpoint(reserve.Addr())
	reserve.Close()
	id, _ := identity.NewID()
	allowID, _ := identity.NewID()
	denyID, _ := identity.NewID()
	state := client.Empty()
	state.LocalInbounds = []client.LocalInbound{{ID: id, Name: "protected cover", Kind: "tunnel", Listen: endpoint, Tunnel: &client.TunnelSettings{Target: guardEndpoint(cover.Addr()), Network: "tcp"}, Sniffing: &client.SniffingPolicy{Enabled: true, Protocols: []string{"tls"}, RouteOnly: true}}}
	state.Network.Route.Rules = []P.RouteRule{{ID: allowID, Name: "explicit A B", Match: P.RuleMatch{LocalInbounds: []identity.ID{id}, SniffedDomains: []string{nameA, nameB}}, Action: P.Action{Kind: P.Direct}}, {ID: denyID, Name: "block other guard traffic", Match: P.RuleMatch{LocalInbounds: []identity.ID{id}}, Action: P.Action{Kind: P.Reject}}}
	guard := clientruntime.New()
	r, _ := registry.NewOutbounds()
	prepared, e := guard.Prepare(ctx, state, nil, r)
	if e != nil {
		t.Fatal(e)
	}
	if e = prepared.Activate(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if e := guard.Close(cleanup); e != nil {
			t.Error(e)
		}
	})
	private, publicKey, e := vl.GenerateServerKey()
	if e != nil {
		t.Fatal(e)
	}
	newID := func() identity.ID {
		id, e := identity.NewID()
		if e != nil {
			t.Fatal(e)
		}
		return id
	}
	stamp := identity.NewStamp(time.Now())
	inboundID, accountID, credentialID := newID(), newID(), newID()
	publicSocket, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	publicEndpoint := guardEndpoint(publicSocket.Addr())
	publicSocket.Close()
	settings := vl.Settings{Security: vl.Reality, Flow: vl.Vision, Transport: "tcp", PacketEncoding: "xudp", Reality: &vl.RealitySettings{ServerName: nameA, ServerNames: []string{nameA, nameB, nameC}, PublicKey: publicKey, ShortIDs: []vl.ShortID{"abcd"}, Target: endpoint}}
	data, _ := json.Marshal(settings)
	serverCredential := access.Credential{ID: credentialID, OwnerAccountID: &accountID, Kind: access.UUID, Schema: 1, State: "active", Stamp: stamp, Payload: access.UUIDPayload{UUID: secret.New(string(newID()))}}
	in := ports.RuntimeIntent{Inbound: access.Inbound{ID: inboundID, NodeID: newID(), Name: "REALITY Vision guarded", Protocol: vl.Key(vl.Reality), Engine: "native", Enabled: true, Listeners: []access.Listener{{ID: newID(), Transport: "tcp", Endpoint: publicEndpoint}}, DisplayEndpoints: []access.DisplayEndpoint{{ID: newID(), Endpoint: publicEndpoint}}, Settings: access.Settings{Schema: 1, Data: data}, Stamp: stamp}, Credentials: []access.Credential{serverCredential}, Bindings: []access.Binding{{ID: newID(), AccountID: accountID, InboundID: inboundID, CredentialID: credentialID, Enabled: true, Stamp: stamp}}, ServerCredentials: []access.Credential{{ID: newID(), OwnerInboundID: &inboundID, Kind: access.PrivateKey, Schema: 1, State: "active", Payload: private, Stamp: stamp}}}
	nodeID := newID()
	credential := serverCredential
	credential.ID = newID()
	credential.OwnerAccountID = nil
	credential.OwnerNodeID = &nodeID
	options, _ := json.Marshal(vl.ClientOptions{Security: vl.Reality, Flow: vl.Vision, PacketEncoding: "xudp"})
	node := client.RemoteNode{ID: nodeID, Name: "native Vision client", Protocol: vl.Key(vl.Reality), Endpoint: publicEndpoint, CredentialID: credential.ID, Transport: client.Transport{Kind: "tcp"}, Security: client.Security{Kind: "reality", TLS: access.ClientTLS{Enabled: true, Trust: "reality", ServerName: nameA, RealityPublicKey: string(publicKey), RealityShortID: "abcd"}}, Options: client.Options{Schema: 1, Data: options}}
	runtime, e := (native.VLESSCompiler{}).Compile(ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	h := runtime.(ports.RuntimeHandle)
	if e = h.Start(ctx); e != nil {
		t.Fatal(e)
	}
	h.Activate()
	t.Cleanup(func() {
		if e := h.Close(context.Background()); e != nil {
			t.Error(e)
		}
	})
	public := net.JoinHostPort(node.Endpoint.Host, strconv.Itoa(int(node.Endpoint.Port)))
	for _, name := range []string{nameA, nameB} {
		t.Run("unauthenticated-cover-"+name, func(t *testing.T) {
			before := count.Load()
			raw, e := net.DialTimeout("tcp", public, time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(5 * time.Second))
			// Name B intentionally differs from the local fixture's certificate. This
			// probe verifies transparent forwarding; authenticated path below verifies certificates.
			c := tls.Client(raw, &tls.Config{ServerName: name, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
			if e = c.HandshakeContext(ctx); e != nil {
				t.Fatal("cover flow", e)
			}
			if e = guardExchange(c, []byte("cover payload unchanged")); e != nil {
				t.Fatal(e)
			}
			c.Close()
			if count.Load() != before+1 {
				t.Fatal("cover did not pass through configured local target")
			}
		})
	}
	// Authenticated payload SNI intentionally has no guard allow rule. REALITY
	// handshake policy must never become a proxy-traffic domain whitelist.
	appName := "application-not-guard-allow.test"
	appMaterial := testkit.TLSForName(t, appName)
	appCert, _ := os.ReadFile(appMaterial.CertificateFile)
	appKey, _ := os.ReadFile(appMaterial.PrivateKeyFile)
	appPair, e := tls.X509KeyPair(appCert, appKey)
	clear(appKey)
	if e != nil {
		t.Fatal(e)
	}
	appTLS := &tls.Config{Certificates: []tls.Certificate{appPair}, MinVersion: tls.VersionTLS13}
	for _, name := range []string{nameA, nameB} {
		t.Run("authenticated-Vision-"+name, func(t *testing.T) {
			n := node
			n.Security.TLS.ServerName = name
			d, e := (native.VLESSOutboundFactory{}).Build(ctx, n, credential)
			if e != nil {
				t.Fatal(e)
			}
			defer d.Close()
			app := guardEcho(t, appTLS)
			stream, e := d.DialContext(ctx, guardEndpoint(app.Addr()))
			if e != nil {
				t.Fatal("REALITY through guard", e)
			}
			defer stream.Close()
			stream.SetDeadline(time.Now().Add(5 * time.Second))
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM([]byte(appMaterial.CACertificate))
			inner := tls.Client(stream, &tls.Config{ServerName: appName, RootCAs: roots, MinVersion: tls.VersionTLS13})
			if e = inner.HandshakeContext(ctx); e != nil {
				t.Fatal("Vision inner TLS", e)
			}
			if e = guardExchange(inner, bytes.Repeat([]byte("authenticated Vision"), 16384)); e != nil {
				t.Fatal(e)
			}
			inner.Close()
		})
	}
	if e = guard.WaitIdle(ctx); e != nil {
		t.Fatal(e)
	}
	for _, probe := range []struct {
		name string
		data []byte
	}{{"handshake-only C", testkit.ClientHello(t, nameC, tls.VersionTLS13)}, {"wrong SNI", testkit.ClientHello(t, "wrong.test", tls.VersionTLS13)}, {"missing SNI", testkit.ClientHello(t, "", tls.VersionTLS13)}, {"HTTP", []byte("GET / HTTP/1.1\r\nHost: " + nameA + "\r\n\r\n")}, {"malformed TLS", []byte{22, 3, 3, 0, 4, 1, 255, 255, 255}}} {
		t.Run(probe.name, func(t *testing.T) {
			before := count.Load()
			raw, e := net.DialTimeout("tcp", public, time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(6 * time.Second))
			raw.Write(probe.data)
			raw.(*net.TCPConn).CloseWrite()
			var b [1]byte
			n, e := raw.Read(b[:])
			if n != 0 || e == nil {
				t.Fatal("blocked probe received target bytes")
			}
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				t.Fatal("probe held open", e)
			}
			if e = guard.WaitIdle(ctx); e != nil {
				t.Fatal(e)
			}
			if count.Load() != before {
				t.Fatal("blocked probe reached controlled cover target")
			}
		})
	}
	status := guard.Status(state, nil)
	if len(status.TunnelGuards) != 1 || status.TunnelGuards[0].Stats.Denied == 0 || status.TunnelGuards[0].Stats.Allowed < 4 {
		t.Fatal("topology did not exercise native guard", status.TunnelGuards)
	}
	t.Logf("controlled cover connections=%d; guard=%+v", count.Load(), status.TunnelGuards[0].Stats)
}

func guardEndpoint(a net.Addr) access.Endpoint {
	v := a.(*net.TCPAddr)
	return access.Endpoint{Host: v.IP.String(), Port: uint16(v.Port)}
}

func guardExchange(c net.Conn, p []byte) error {
	done := make(chan error, 1)
	go func() { _, e := c.Write(p); done <- e }()
	b := make([]byte, len(p))
	_, e := io.ReadFull(c, b)
	if e != nil {
		c.Close()
	}
	writeErr := <-done
	if e != nil {
		return e
	}
	if writeErr != nil {
		return writeErr
	}
	if !bytes.Equal(b, p) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func guardEcho(t *testing.T, tc *tls.Config) net.Listener {
	t.Helper()
	l, e := tls.Listen("tcp", "127.0.0.1:0", tc)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			wg.Go(func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				io.Copy(c, c)
			})
		}
	})
	t.Cleanup(func() { l.Close(); wg.Wait() })
	return l
}
