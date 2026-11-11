//go:build with_utls

package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	streamcfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/exporter"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	vl "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/tlsconfig"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/vless/encryption"
)

// These fixtures exercise current production compilers and outbound owners;
// the historical encrypted wire tests separately cover cryptographic branches.
type encryptionFixture struct {
	in         ports.RuntimeIntent
	node       client.RemoteNode
	credential access.Credential
	target     access.Endpoint
	innerTLS   *tls.Config
}

func encryptionID(t *testing.T) identity.ID {
	t.Helper()
	id, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func encryptionEndpoint(t *testing.T, address net.Addr) access.Endpoint {
	t.Helper()
	host, port, err := net.SplitHostPort(address.String())
	if err != nil {
		t.Fatal(err)
	}
	var number uint16
	for _, digit := range port {
		number = number*10 + uint16(digit-'0')
	}
	return access.Endpoint{Host: host, Port: number}
}

func encryptionAddress(e access.Endpoint) string { return net.JoinHostPort(e.Host, portString(e.Port)) }

func encryptionPort(t *testing.T) access.Endpoint {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := encryptionEndpoint(t, l.Addr())
	_ = l.Close()
	return endpoint
}

func encryptionEcho(t *testing.T, tc *tls.Config) access.Endpoint {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if tc != nil {
		l = tls.NewListener(l, tc)
	}
	var mu sync.Mutex
	connections := map[net.Conn]bool{}
	closed := false
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				_ = c.Close()
				return
			}
			connections[c] = true
			workers.Add(1)
			mu.Unlock()
			go func() {
				defer workers.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(15 * time.Second))
				_, _ = io.Copy(c, c)
				mu.Lock()
				delete(connections, c)
				mu.Unlock()
			}()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		closed = true
		for c := range connections {
			_ = c.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return encryptionEndpoint(t, l.Addr())
}

func newEncryptionFixture(t *testing.T, security vl.Security, flow vl.Flow, mode, kind string) encryptionFixture {
	t.Helper()
	sni := "encryption.synthetic.test"
	material := testkit.TLSForName(t, sni)
	if _, key, err := tlsconfig.Snapshot(material); err != nil {
		t.Fatal("synthetic TLS snapshot:", err)
	} else {
		clear(key)
	}
	cert, err := tls.LoadX509KeyPair(material.CertificateFile, material.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	secureTarget := encryptionEcho(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	target := encryptionEcho(t, nil)
	ca := x509.NewCertPool()
	if !ca.AppendCertsFromPEM([]byte(material.CACertificate)) {
		t.Fatal("invalid synthetic CA")
	}
	inner := &tls.Config{RootCAs: ca, ServerName: sni, MinVersion: tls.VersionTLS13}
	if flow == vl.Vision {
		target = secureTarget
	}
	private, public, err := encryption.Generate("mlkem768", mode, "0rtt", "600s", "100-35-35")
	if err != nil {
		t.Fatal(err)
	}
	settings := vl.Settings{Encryption: public, Security: security, Flow: flow, Transport: "tcp", PacketEncoding: "xudp"}
	transport := streamcfg.Config{Kind: kind}
	if kind == "ws" || kind == "httpupgrade" || kind == "xhttp" {
		transport.Path = "/encrypted"
	}
	if kind == "grpc" {
		transport.ServiceName = "encrypted"
	}
	if kind != "tcp" {
		settings.Stream = &transport
	}
	endpoint := encryptionPort(t)
	if kind == "mkcp" {
		l, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		endpoint = encryptionEndpoint(t, l.LocalAddr())
		_ = l.Close()
	}
	stamp := identity.NewStamp(time.Now())
	in := ports.RuntimeIntent{Inbound: access.Inbound{ID: encryptionID(t), NodeID: encryptionID(t), Name: "encryption-fixture", Protocol: vl.Key(security), Engine: "native", Enabled: true, Listeners: []access.Listener{{ID: encryptionID(t), Transport: transport.Carrier(), Endpoint: endpoint}}, DisplayEndpoints: []access.DisplayEndpoint{{ID: encryptionID(t), Endpoint: endpoint}}, Stamp: stamp}}
	in.ServerCredentials = []access.Credential{{ID: encryptionID(t), OwnerInboundID: &in.Inbound.ID, Kind: access.PrivateKey, Schema: 1, State: "active", Payload: access.PrivateKeyPayload{Algorithm: "vless-encryption", Material: secret.New(private)}, Stamp: stamp}}
	nodeSecurity := client.Security{Kind: string(security)}
	if security == vl.TLS {
		settings.TLS = &material
		nodeSecurity.TLS = access.ClientTLS{Enabled: true, ServerName: sni, Trust: "explicit_ca", CACertificate: material.CACertificate}
	}
	if security == vl.Reality {
		key, pub, err := vl.GenerateServerKey()
		if err != nil {
			t.Fatal(err)
		}
		settings.Reality = &vl.RealitySettings{PublicKey: pub, ServerName: sni, ShortIDs: []vl.ShortID{"abcd"}, Target: secureTarget}
		// Encryption intentionally precedes the independent REALITY key.
		in.ServerCredentials = append(in.ServerCredentials, access.Credential{ID: encryptionID(t), OwnerInboundID: &in.Inbound.ID, Kind: access.PrivateKey, Schema: 1, State: "active", Payload: key, Stamp: stamp})
		nodeSecurity.TLS = access.ClientTLS{Enabled: true, ServerName: sni, Trust: "reality", RealityPublicKey: string(pub), RealityShortID: "abcd"}
	}
	in.Inbound.Settings = access.Settings{Schema: 1}
	in.Inbound.Settings.Data, _ = json.Marshal(settings)
	account, user := encryptionID(t), encryptionID(t)
	credential := access.Credential{ID: encryptionID(t), OwnerAccountID: &account, Kind: access.UUID, Schema: 1, State: "active", Payload: access.UUIDPayload{UUID: secret.New(string(user))}, Stamp: stamp}
	in.Credentials = []access.Credential{credential}
	in.Bindings = []access.Binding{{ID: encryptionID(t), AccountID: account, InboundID: in.Inbound.ID, CredentialID: credential.ID, Enabled: true, Stamp: stamp}}
	nid := encryptionID(t)
	credential.OwnerAccountID = nil
	credential.OwnerNodeID = &nid
	options, _ := json.Marshal(vl.ClientOptions{Encryption: public, Security: security, Flow: flow, PacketEncoding: "xudp"})
	node := client.RemoteNode{ID: nid, Name: "encrypted-native", Protocol: vl.Key(security), Endpoint: endpoint, CredentialID: credential.ID, Transport: transport, Security: nodeSecurity, Options: client.Options{Schema: 1, Data: options}}
	return encryptionFixture{in: in, node: node, credential: credential, target: target, innerTLS: inner}
}

func (f encryptionFixture) start(t *testing.T, ctx context.Context) *vlessHandle {
	t.Helper()
	p, err := (VLESSCompiler{}).Compile(ctx, f.in)
	if err != nil {
		t.Fatal(err)
	}
	h := p.(*vlessHandle)
	t.Cleanup(func() {
		if err := h.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	if err = h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	h.Activate()
	return h
}

func (f encryptionFixture) build(t *testing.T, ctx context.Context) ports.ClientDialer {
	t.Helper()
	d, err := (VLESSOutboundFactory{}).Build(ctx, f.node, f.credential)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Error(err)
		}
	})
	return d
}

func encryptionExchange(c net.Conn, size int) error {
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	payload := bytes.Repeat([]byte{0, 1, 255, 23, 3, 3, 128}, (size+6)/7)[:size]
	write := make(chan error, 1)
	go func() { _, err := io.Copy(c, bytes.NewReader(payload)); write <- err }()
	actual := make([]byte, size)
	_, err := io.ReadFull(c, actual)
	if err != nil {
		_ = c.Close()
		<-write
		return err
	}
	if err = <-write; err != nil {
		return err
	}
	if !bytes.Equal(actual, payload) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (f encryptionFixture) traffic(t *testing.T, c net.Conn) {
	t.Helper()
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	options, _ := vl.DecodeClientOptions(f.node.Options.Data)
	if options.Flow == vl.Vision {
		secure := tls.Client(c, f.innerTLS)
		if err := secure.Handshake(); err != nil {
			t.Fatal("inner TLS Vision transition:", err)
		}
		c = secure
	}
	if err := encryptionExchange(c, 131079); err != nil {
		t.Fatal("encrypted real traffic:", err)
	}
}

func TestVLESSEncryptionNativeSecurityVision(t *testing.T) {
	for _, security := range []vl.Security{vl.Plain, vl.TLS, vl.Reality} {
		for _, flow := range []vl.Flow{vl.NoFlow, vl.Vision} {
			for _, mode := range []string{"native", "xorpub", "random"} {
				t.Run(string(security)+"/"+string(flow)+"/"+mode, func(t *testing.T) {
					ctx := underlay.WithFactory(context.Background(), underlay.New())
					f := newEncryptionFixture(t, security, flow, mode, "tcp")
					h := f.start(t, ctx)
					d := f.build(t, ctx)
					for range 2 {
						c, err := d.DialContext(ctx, f.target)
						if err != nil {
							t.Fatal(err)
						}
						f.traffic(t, c)
					}
					if err := d.Close(); err != nil {
						t.Fatal(err)
					}
					if _, err := d.DialContext(ctx, f.target); err == nil {
						t.Fatal("closed outbound accepted work")
					}
					if err := h.Close(ctx); err != nil {
						t.Fatal(err)
					}
					l, err := net.Listen("tcp4", encryptionAddress(f.node.Endpoint))
					if err != nil {
						t.Fatal("encrypted listener retained:", err)
					}
					_ = l.Close()
				})
			}
		}
	}
}

func TestVLESSEncryptionExistingCarriersAndXUDP(t *testing.T) {
	for _, kind := range []string{"ws", "httpupgrade", "grpc", "xhttp", "mkcp"} {
		t.Run(kind, func(t *testing.T) {
			ctx := underlay.WithFactory(context.Background(), underlay.New())
			f := newEncryptionFixture(t, vl.TLS, vl.NoFlow, "random", kind)
			f.start(t, ctx)
			d := f.build(t, ctx)
			c, err := d.DialContext(ctx, f.target)
			if err != nil {
				t.Fatal(err)
			}
			f.traffic(t, c)
			packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				p := make([]byte, 2048)
				n, addr, err := packet.ReadFrom(p)
				if err == nil {
					_, _ = packet.WriteTo(p[:n], addr)
				}
			}()
			t.Cleanup(func() { _ = packet.Close(); <-done })
			pc, err := d.(ports.ClientPacketDialer).ListenPacket(ctx, encryptionEndpoint(t, packet.LocalAddr()))
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
			payload := []byte("encrypted XUDP payload")
			if _, err = pc.WriteTo(payload, packet.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			p := make([]byte, 128)
			n, _, err := pc.ReadFrom(p)
			if err != nil || !bytes.Equal(payload, p[:n]) {
				t.Fatal("XUDP", err)
			}
		})
	}
}

func TestVLESSEncryptionRuntimeCredentialBoundaries(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	f := newEncryptionFixture(t, vl.Plain, vl.NoFlow, "random", "tcp")
	for _, mutate := range []func(*ports.RuntimeIntent){
		func(in *ports.RuntimeIntent) { in.ServerCredentials = nil },
		func(in *ports.RuntimeIntent) {
			in.ServerCredentials = append(in.ServerCredentials, in.ServerCredentials[0])
		},
		func(in *ports.RuntimeIntent) { id := encryptionID(t); in.ServerCredentials[0].OwnerInboundID = &id },
		func(in *ports.RuntimeIntent) { in.ServerCredentials[0].State = "revoked" },
		func(in *ports.RuntimeIntent) {
			in.ServerCredentials[0].Payload = access.PrivateKeyPayload{Algorithm: "vless-encryption", Material: secret.New("synthetic-private-key")}
		},
	} {
		in := f.in
		in.ServerCredentials = append([]access.Credential(nil), f.in.ServerCredentials...)
		mutate(&in)
		if _, err := (VLESSCompiler{}).Compile(ctx, in); err == nil || strings.Contains(err.Error(), "synthetic-private-key") {
			t.Fatal("invalid server credentials accepted/disclosed", err)
		}
	}
	f.start(t, ctx)
	f.credential.Payload = access.UUIDPayload{UUID: secret.New(string(encryptionID(t)))}
	d := f.build(t, ctx)
	c, err := d.DialContext(ctx, f.target)
	if err == nil {
		defer c.Close()
		if err = encryptionExchange(c, 17); err == nil {
			t.Fatal("wrong UUID relayed")
		}
	}
	// A valid but different encryption key must fail before any VLESS payload;
	// the adapter must never retry the connection as plaintext.
	f.credential = f.in.Credentials[0]
	f.credential.OwnerAccountID = nil
	f.credential.OwnerNodeID = &f.node.ID
	_, wrongKey, err := encryption.Generate("mlkem768", "random", "0rtt", "600s", "100-35-35")
	if err != nil {
		t.Fatal(err)
	}
	options, _ := vl.DecodeClientOptions(f.node.Options.Data)
	options.Encryption = wrongKey
	f.node.Options.Data, _ = json.Marshal(options)
	wrong := f.build(t, ctx)
	if c, err := wrong.DialContext(ctx, f.target); err == nil {
		_ = c.Close()
		t.Fatal("wrong encryption key accepted")
	}
}

func TestVLESSEncryptionOutboundCloseCancelsHandshake(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	f := newEncryptionFixture(t, vl.Plain, vl.NoFlow, "random", "tcp")
	listener, err := net.Listen("tcp4", encryptionAddress(f.node.Endpoint))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	d := f.build(t, ctx)
	result := make(chan error, 1)
	go func() {
		c, err := d.DialContext(ctx, f.target)
		if c != nil {
			_ = c.Close()
		}
		result <- err
	}()
	select {
	case c := <-accepted:
		defer c.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("outbound did not dial")
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("stalled handshake succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("outbound close did not join pending handshake")
	}
}

func encryptionReference(t *testing.T, binary string, configuration any, endpoint access.Endpoint) {
	t.Helper()
	dir := t.TempDir()
	data, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "peer.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "peer.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "run", "-config", path)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.Env = append(os.Environ(), "XRAY_CONE_DISABLED=true")
	if err = cmd.Start(); err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	joined := false
	t.Cleanup(func() {
		if !joined {
			_ = cmd.Process.Kill()
			<-done
		}
		_ = log.Close()
		if t.Failed() {
			data, _ := os.ReadFile(logPath)
			t.Log(string(data))
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp4", encryptionAddress(endpoint), 20*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		select {
		case err := <-done:
			joined = true
			t.Fatal("reference exited:", err)
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("reference did not listen")
}

func encryptionSOCKS(endpoint, target access.Endpoint) (net.Conn, error) {
	c, err := net.DialTimeout("tcp4", encryptionAddress(endpoint), time.Second)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	failed := true
	defer func() {
		if failed {
			_ = c.Close()
		}
	}()
	if _, err = c.Write([]byte{5, 1, 0}); err != nil {
		return nil, err
	}
	reply := make([]byte, 2)
	if _, err = io.ReadFull(c, reply); err != nil || !bytes.Equal(reply, []byte{5, 0}) {
		return nil, io.ErrUnexpectedEOF
	}
	request := append([]byte{5, 1, 0, 1}, net.ParseIP(target.Host).To4()...)
	request = append(request, byte(target.Port>>8), byte(target.Port))
	if _, err = c.Write(request); err != nil {
		return nil, err
	}
	reply = make([]byte, 10)
	if _, err = io.ReadFull(c, reply); err != nil || reply[1] != 0 {
		return nil, io.ErrUnexpectedEOF
	}
	failed = false
	return c, nil
}

func TestVLESSEncryptionPinnedRuntimeInterop(t *testing.T) {
	binary := os.Getenv("SPLICORE_VLESS_ENCRYPTION_REFERENCE")
	if binary == "" {
		t.Skip("independent pinned Xray peer not configured")
	}
	version, err := exec.Command(binary, "version").Output()
	if err != nil || !bytes.Contains(version, []byte("26.10.21")) || !bytes.Contains(version, []byte("1b1647c")) {
		t.Fatal("reference identity mismatch")
	}
	for _, security := range []vl.Security{vl.Plain, vl.TLS, vl.Reality} {
		for _, flow := range []vl.Flow{vl.NoFlow, vl.Vision} {
			for _, mode := range []string{"native", "xorpub", "random"} {
				for _, direction := range []string{"native-client", "native-server"} {
					t.Run(string(security)+"/"+string(flow)+"/"+mode+"/"+direction, func(t *testing.T) {
						ctx := underlay.WithFactory(context.Background(), underlay.New())
						f := newEncryptionFixture(t, security, flow, mode, "tcp")
						var settings vl.Settings
						_ = json.Unmarshal(f.in.Inbound.Settings.Data, &settings)
						stream := map[string]any{"network": "raw", "security": string(security)}
						isClient := direction == "native-client"
						if security == vl.TLS {
							if isClient {
								stream["tlsSettings"] = map[string]any{"certificates": []any{map[string]any{"certificateFile": settings.TLS.CertificateFile, "keyFile": settings.TLS.PrivateKeyFile}}}
							} else {
								stream["tlsSettings"] = map[string]any{"serverName": f.node.Security.TLS.ServerName, "allowInsecure": false, "certificates": []any{map[string]any{"certificate": strings.Split(strings.TrimSpace(f.node.Security.TLS.CACertificate), "\n"), "usage": "verify"}}}
							}
						}
						if security == vl.Reality {
							if isClient {
								stream["realitySettings"] = map[string]any{"target": encryptionAddress(settings.Reality.Target), "serverNames": []string{settings.Reality.ServerName}, "privateKey": realityServerKey(f.in.ServerCredentials), "shortIds": []string{"abcd"}}
							} else {
								stream["realitySettings"] = map[string]any{"serverName": f.node.Security.TLS.ServerName, "publicKey": f.node.Security.TLS.RealityPublicKey, "shortId": "abcd", "fingerprint": "chrome"}
							}
						}
						configuration := map[string]any{"log": map[string]any{"loglevel": "warning"}}
						id := f.credential.Payload.(access.UUIDPayload).UUID.Reveal()
						user := map[string]any{"id": id}
						if flow == vl.Vision {
							user["flow"] = string(flow)
						}
						peerEndpoint := f.node.Endpoint
						var dial func(access.Endpoint) (net.Conn, error)
						if isClient {
							configuration["inbounds"] = []any{map[string]any{"listen": peerEndpoint.Host, "port": peerEndpoint.Port, "protocol": "vless", "settings": map[string]any{"clients": []any{user}, "decryption": f.in.ServerCredentials[0].Payload.(access.PrivateKeyPayload).Material.Reveal()}, "streamSettings": stream}}
							configuration["outbounds"] = []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.0/8"}}}}}}
							d := f.build(t, ctx)
							dial = func(target access.Endpoint) (net.Conn, error) { return d.DialContext(ctx, target) }
						} else {
							f.start(t, ctx)
							peerEndpoint = encryptionPort(t)
							configuration["inbounds"] = []any{map[string]any{"listen": peerEndpoint.Host, "port": peerEndpoint.Port, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}}
							user["encryption"] = settings.Encryption
							profile, err := (vl.Module{Security: security}).BuildClientProfile(ctx, ports.AuthorizedBinding{Inbound: f.in.Inbound, Binding: f.in.Bindings[0], Credential: f.in.Credentials[0]})
							if err != nil {
								t.Fatal(err)
							}
							projection, err := (exporter.VLESS{Target: ports.Xray}).Export(ctx, profile, ports.ExportTarget{Format: ports.Xray, ClientVersion: "26.10.21"})
							if err != nil {
								t.Fatal(err)
							}
							var outbound map[string]any
							if err := json.Unmarshal(projection, &outbound); err != nil {
								t.Fatal(err)
							}
							configuration["outbounds"] = []any{outbound}
							dial = func(target access.Endpoint) (net.Conn, error) { return encryptionSOCKS(peerEndpoint, target) }
						}
						encryptionReference(t, binary, configuration, peerEndpoint)
						for range 2 {
							c, err := dial(f.target)
							if err != nil {
								t.Fatal(err)
							}
							f.traffic(t, c)
						}
					})
				}
			}
		}
	}
}
