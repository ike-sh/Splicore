//go:build with_quic && with_utls

package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/exporter"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	vl "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/vless/backend"
	"github.com/ike-sh/Splicore/protocol/vless/encryption"
)

func phase33Intent(t *testing.T, protocol, mode string) (ports.RuntimeIntent, client.RemoteNode, access.Credential) {
	t.Helper()
	in, n, credential := sharedIntent(t, protocol, "xhttp", true)
	n.Security.TLS.ALPN = []string{"h3"}
	n.Transport.XHTTP = &cfg.XHTTP{Mode: mode}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(in.Inbound.Settings.Data, &fields); err != nil {
		t.Fatal(err)
	}
	fields["alpn"], _ = json.Marshal(n.Security.TLS.ALPN)
	fields["stream_transport"], _ = json.Marshal(n.Transport)
	in.Inbound.Settings.Data, _ = json.Marshal(fields)
	in.Inbound.Listeners[0].Transport = "udp"
	return in, n, credential
}

func TestPhase33NativeProtocols(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	tcp := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	udp := trojanUDP(t)
	for _, protocol := range []string{"vless", "vmess", "trojan"} {
		for _, mode := range []string{"auto", "packet-up", "stream-up", "stream-one"} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				in, n, credential := phase33Intent(t, protocol, mode)
				h, endpoint := startMKCP(t, ctx, protocol, in, "127.0.0.1")
				n.Endpoint = endpoint
				d := sharedBuild(t, ctx, n, credential)
				sharedPayload(t, d, tcp, udp)
				sharedPayload(t, d, tcp, udp)
				d.Close()
				h.Close(ctx)
				if h.Stats().Active != 0 {
					t.Fatal("retained native H3 session")
				}
			})
		}
	}
}

func phase33Reference(t *testing.T) string {
	t.Helper()
	binary := os.Getenv("SPLICORE_XHTTP_H3_REFERENCE")
	if binary == "" {
		t.Fatal("Phase33 qualification requires SPLICORE_XHTTP_H3_REFERENCE pinned v26.10.21 binary")
	}
	file, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err = io.Copy(digest, file); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"linux/amd64":   "a27e3f95ab6ce270956d0cecd32eda4686a811afc71c64a6a734a3dede14883e",
		"windows/amd64": "c77a00eb84fb93ae044c2d771a1cabcc033b81e487253fbc35b12df6879c1e15",
	}[runtime.GOOS+"/"+runtime.GOARCH]
	if want == "" || hex.EncodeToString(digest.Sum(nil)) != want {
		t.Fatal("Phase33 reference binary digest mismatch")
	}
	return binary
}

func phase33Peer(t *testing.T, binary string, config map[string]any, server bool) {
	t.Helper()
	root := t.TempDir()
	if external := os.Getenv("SPLICORE_PHASE33_PEER_LOGS"); external != "" {
		root = filepath.Join(external, testkit.EvidenceName(t.Name()))
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	file, logPath := filepath.Join(root, "config.json"), filepath.Join(root, "peer.log")
	if err = os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "run", "-config", file)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.Env = append(os.Environ(), "XRAY_CONE_DISABLED=true")
	if err = cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-done; log.Close() })
	marker := "[Warning] core: Xray "
	if server {
		marker = "listening QUIC for XHTTP/3"
	}
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		data, _ := os.ReadFile(logPath)
		if bytes.Contains(data, []byte(marker)) {
			return
		}
		select {
		case err := <-done:
			done <- err
			t.Fatalf("pinned reference rejected profile: %v; peer.log:\n%s", err, data)
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("pinned reference startup timeout; see peer.log")
}

func phase33PeerConfig(t *testing.T, protocol, direction string, in ports.RuntimeIntent, n client.RemoteNode, credential access.Credential, socks access.Endpoint) map[string]any {
	t.Helper()
	role := "server"
	if direction == "splicore-server" {
		role = "client"
	}
	root := sharedPeerConfig(t, "xray-core", role, protocol, in, n, credential, socks)
	section := "inbounds"
	if role == "client" {
		section = "outbounds"
	}
	node := root[section].([]any)[0].(map[string]any)
	stream := node["streamSettings"].(map[string]any)
	delete(stream, "wsSettings")
	stream["network"] = "xhttp"
	b, _ := json.Marshal(n.Transport.XHTTP)
	var options map[string]any
	_ = json.Unmarshal(b, &options)
	options["path"], options["host"] = n.Transport.Path, n.Transport.Host
	stream["xhttpSettings"] = options
	tls := stream["tlsSettings"].(map[string]any)
	tls["alpn"] = []string{"h3"}
	if protocol == "vless" {
		settings := node["settings"].(map[string]any)
		clientOptions, _ := vl.DecodeClientOptions(n.Options.Data)
		if role == "server" {
			if clientOptions.Flow == vl.Vision {
				settings["clients"].([]any)[0].(map[string]any)["flow"] = string(vl.Vision)
			}
			if len(in.ServerCredentials) > 0 {
				settings["decryption"] = in.ServerCredentials[len(in.ServerCredentials)-1].Payload.(access.PrivateKeyPayload).Material.Reveal()
			}
		} else {
			clientOptions, _ := vl.DecodeClientOptions(n.Options.Data)
			user := settings["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
			if clientOptions.Flow == vl.Vision {
				user["flow"] = string(vl.Vision)
			}
			if clientOptions.Encryption != "" {
				user["encryption"] = clientOptions.Encryption
			}
		}
	}
	if role == "server" {
		// The pinned release blocks private proxy destinations by default.
		// Permit only the test's owned loopback echo endpoints.
		root["outbounds"].([]any)[0].(map[string]any)["settings"] = map[string]any{
			"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32", "::1/128"}}},
		}
	}
	if role == "client" && protocol == "vless" {
		opts, _ := vl.DecodeClientOptions(n.Options.Data)
		profile := clientprofile.Profile{
			Schema: 1, ID: n.ID, Protocol: n.Protocol,
			Endpoint: n.Endpoint, Credentials: credential.Payload, Transport: n.Transport,
			TLS: n.Security.TLS, UDPPayload: opts.Flow != vl.Vision,
			Options: access.Settings{Schema: 1, Data: n.Options.Data},
		}
		data, err := (exporter.VLESS{Target: ports.Xray}).Export(context.Background(), profile, ports.ExportTarget{Format: ports.Xray, ClientVersion: "26.10.21"})
		if err != nil {
			t.Fatal("H3 public profile export", err)
		}
		var outbound map[string]any
		if err = json.Unmarshal(data, &outbound); err != nil {
			t.Fatal(err)
		}
		root["outbounds"] = []any{outbound}
	}
	return root
}

func phase33SOCKS(t *testing.T) access.Endpoint {
	t.Helper()
	return access.Endpoint{Host: "127.0.0.1", Port: uint16(testkit.PeerPort(t, "tcp"))}
}

func TestPhase33PinnedProtocols(t *testing.T) {
	binary := phase33Reference(t)
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	tcp := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	udp := trojanUDP(t)
	for _, protocol := range []string{"vless", "vmess", "trojan"} {
		for _, mode := range []string{"auto", "packet-up", "stream-up", "stream-one"} {
			for _, direction := range []string{"splicore-client", "splicore-server"} {
				t.Run(protocol+"/"+mode+"/"+direction, func(t *testing.T) {
					in, n, credential := phase33Intent(t, protocol, mode)
					socks := phase33SOCKS(t)
					if direction == "splicore-server" {
						h, endpoint := startMKCP(t, ctx, protocol, in, "127.0.0.1")
						n.Endpoint = endpoint
						defer h.Close(ctx)
					}
					phase33Peer(t, binary, phase33PeerConfig(t, protocol, direction, in, n, credential, socks), direction == "splicore-client")
					if direction == "splicore-client" {
						d := sharedBuild(t, ctx, n, credential)
						defer d.Close()
						sharedPayload(t, d, tcp, udp)
					} else {
						sharedExternalPayload(t, socks, tcp, udp)
					}
					t.Log("actual pinned Xray TCP/UDP payload and reply PASS")
				})
			}
		}
	}
}

func TestPhase33PinnedEncryption(t *testing.T) {
	binary := phase33Reference(t)
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	tcp := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	udp := trojanUDP(t)
	for ai, auth := range []string{"x25519", "mlkem768"} {
		for mi, mode := range []string{"native", "xorpub", "random"} {
			for _, policy := range []string{"1rtt", "0rtt"} {
				for _, direction := range []string{"self", "splicore-client", "splicore-server"} {
					t.Run(auth+"/"+mode+"/"+policy+"/"+direction, func(t *testing.T) {
						carrierMode := []string{"packet-up", "stream-up", "stream-one"}[(ai+mi)%3]
						in, n, credential := phase33Intent(t, "vless", carrierMode)
						server, public, err := encryption.Generate(auth, mode, policy, "600s", "100-35-35")
						if err != nil {
							t.Fatal(err)
						}
						var s vl.Settings
						_ = json.Unmarshal(in.Inbound.Settings.Data, &s)
						serverConfig, err := encryption.ParseServer(server)
						if err != nil {
							t.Fatal(err)
						}
						s.Encryption = serverConfig.ClientString(true)
						in.Inbound.Settings.Data, _ = json.Marshal(s)
						key := in.Credentials[0]
						key.OwnerAccountID, key.OwnerInboundID, key.Kind = nil, &in.Inbound.ID, access.PrivateKey
						key.Payload = access.PrivateKeyPayload{Algorithm: "vless-encryption", Material: secret.New(server)}
						in.ServerCredentials = []access.Credential{key}
						options, _ := vl.DecodeClientOptions(n.Options.Data)
						options.Encryption = public
						n.Options.Data, _ = json.Marshal(options)
						var h ports.RuntimeHandle
						if direction != "splicore-client" {
							h, n.Endpoint = startMKCP(t, ctx, "vless", in, "127.0.0.1")
							defer h.Close(ctx)
						}
						socks := phase33SOCKS(t)
						if direction != "self" {
							phase33Peer(t, binary, phase33PeerConfig(t, "vless", direction, in, n, credential, socks), direction == "splicore-client")
						}
						if direction == "splicore-server" {
							for range 2 {
								c, err := phaseSOCKS(socks, tcp)
								if err != nil {
									t.Fatal(err)
								}
								if err = phaseExchange(c, bytes.Repeat([]byte("encrypted H3"), 3000)); err != nil {
									t.Fatal(err)
								}
								c.Close()
							}
							// Stop accepting and join handlers before inspecting private
							// replay state. No production instrumentation or unsafe access.
							serverHandle := h.(*vlessHandle)
							serverHandle.listener.Close()
							serverHandle.wg.Wait()
							states := reflect.ValueOf(serverHandle.decryption).Elem().FieldByName("sessions")
							resumes := 0
							for _, ticket := range states.MapKeys() {
								resumes += states.MapIndex(ticket).Elem().FieldByName("used").Len()
							}
							if (resumes > 0) != (policy == "0rtt") {
								t.Fatal("pinned reverse actual resume mismatch", resumes)
							}
						} else {
							d := sharedBuild(t, ctx, n, credential)
							defer d.Close()
							for iteration := range 2 {
								dialer := d.(*vlessDialer)
								raw, err := dialer.transport.DialContext(ctx)
								if err != nil {
									t.Fatal(err)
								}
								admission, finish := vlessAdmission(ctx, raw, dialer.encryption.HandshakeTimeout())
								encrypted, err := dialer.encryption.Handshake(ctx, admission)
								if err != nil {
									raw.Close()
									finish()
									t.Fatal(err)
								}
								resumed := reflect.ValueOf(encrypted).Elem().FieldByName("resumed").Bool()
								if resumed != (policy == "0rtt" && iteration == 1) {
									t.Fatal("actual Encryption resume mismatch", resumed)
								}
								c, err := backend.ClientFlow(ctx, encrypted, dialer.uuid, tcp, false, "")
								if err == nil {
									err = finish()
								}
								if err == nil {
									err = phaseExchange(c, bytes.Repeat([]byte("encrypted H3"), 3000))
								}
								raw.Close()
								if err != nil {
									t.Fatal(err)
								}
							}
							sharedPayloadBudget(t, d, tcp, udp, 15*time.Second)
						}
						t.Log("auth", auth, "encryption", mode, "policy", policy, "XHTTP", carrierMode, "direction", direction, "actual resumption verified")
					})
				}
			}
		}
	}
}

func TestPhase33PinnedVision(t *testing.T) {
	binary := phase33Reference(t)
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	material := testkit.TLSForName(t, "inner.synthetic.test")
	cert, err := tls.LoadX509KeyPair(material.CertificateFile, material.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(material.CACertificate)) {
		t.Fatal("inner CA")
	}
	target := netaddrEndpoint(vlessEcho(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}).Addr())
	for mi, mode := range []string{"native", "xorpub", "random"} {
		for _, direction := range []string{"self", "splicore-client", "splicore-server"} {
			t.Run(mode+"/"+direction, func(t *testing.T) {
				in, n, credential := phase33Intent(t, "vless", []string{"packet-up", "stream-up", "stream-one"}[mi])
				public := phase32EnableMode(t, &in, mode)
				var s vl.Settings
				_ = json.Unmarshal(in.Inbound.Settings.Data, &s)
				s.Flow = vl.Vision
				in.Inbound.Settings.Data, _ = json.Marshal(s)
				opts, _ := vl.DecodeClientOptions(n.Options.Data)
				opts.Encryption, opts.Flow = public, vl.Vision
				n.Options.Data, _ = json.Marshal(opts)
				if direction != "splicore-client" {
					h, endpoint := startMKCP(t, ctx, "vless", in, "127.0.0.1")
					n.Endpoint = endpoint
					defer h.Close(ctx)
				}
				socks := phase33SOCKS(t)
				if direction != "self" {
					phase33Peer(t, binary, phase33PeerConfig(t, "vless", direction, in, n, credential, socks), direction == "splicore-client")
				}
				var dial func(access.Endpoint) (net.Conn, error)
				if direction == "splicore-server" {
					dial = func(dst access.Endpoint) (net.Conn, error) { return phaseSOCKS(socks, dst) }
				} else {
					d := sharedBuild(t, ctx, n, credential)
					defer d.Close()
					dial = func(dst access.Endpoint) (net.Conn, error) { return d.DialContext(ctx, dst) }
				}
				for range 2 {
					raw, err := dial(target)
					if err != nil {
						t.Fatal(err)
					}
					inner := tls.Client(raw, &tls.Config{ServerName: material.ServerName, RootCAs: roots, MinVersion: tls.VersionTLS13})
					err = phaseExchange(inner, bytes.Repeat([]byte("real inner TLS Vision H3 application"), 40000))
					inner.Close()
					if err != nil {
						t.Fatal("Vision direct transition", err)
					}
				}
			})
		}
	}
	// The pinned server accepts this configuration but rejects actual Vision
	// requests without Encryption: the XHTTP logical stream is not a TLS conn.
	t.Run("plain-reference-reject", func(t *testing.T) {
		in, n, credential := phase33Intent(t, "vless", "stream-one")
		opts, _ := vl.DecodeClientOptions(n.Options.Data)
		opts.Flow = vl.Vision
		n.Options.Data, _ = json.Marshal(opts)
		phase33Peer(t, binary, phase33PeerConfig(t, "vless", "splicore-client", in, n, credential, phase33SOCKS(t)), true)
		opts.Flow = vl.NoFlow
		n.Options.Data, _ = json.Marshal(opts)
		d := sharedBuild(t, ctx, n, credential).(*vlessDialer)
		defer d.Close()
		raw, err := d.transport.DialContext(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Close()
		c, err := backend.ClientFlow(ctx, raw, d.uuid, target, false, string(vl.Vision))
		if err == nil {
			err = phaseExchange(c, []byte("must reject"))
		}
		if err == nil {
			t.Fatal("pinned reference accepted plain Vision H3")
		}
	})
}

func TestPhase33AuthenticationOrdering(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	for _, protocol := range []string{"vless", "vmess", "trojan", "vless-encrypted"} {
		t.Run(protocol, func(t *testing.T) {
			wire := strings.TrimSuffix(protocol, "-encrypted")
			in, n, credential := phase33Intent(t, wire, "stream-one")
			if protocol == "vless-encrypted" {
				public := phase32Enable(t, &in)
				opts, _ := vl.DecodeClientOptions(n.Options.Data)
				opts.Encryption = public
				n.Options.Data, _ = json.Marshal(opts)
			}
			h, endpoint := startMKCP(t, ctx, wire, in, "127.0.0.1")
			defer h.Close(ctx)
			n.Endpoint = endpoint
			if wire == "trojan" {
				credential.Payload = access.PasswordPayload{Password: secret.New("invalid-password")}
			} else {
				credential.Payload = access.UUIDPayload{UUID: secret.New("00000000-0000-4000-8000-000000000099")}
			}
			target, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			d := sharedBuild(t, ctx, n, credential)
			admission, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			c, err := d.DialContext(admission, netaddrEndpoint(target.Addr()))
			if err == nil {
				c.SetDeadline(time.Now().Add(time.Second))
				_, _ = c.Write([]byte("unauthorized request"))
				_, err = c.Read(make([]byte, 1))
				c.Close()
				if err == nil {
					t.Fatal("invalid credential accepted")
				}
			}
			d.Close()
			h.Close(ctx)
			target.SetDeadline(time.Now().Add(50 * time.Millisecond))
			if c, err := target.Accept(); err == nil {
				c.Close()
				t.Fatal("unauthenticated outbound dial")
			}
		})
	}
}

func TestPhase33ManagedDNS(t *testing.T) {
	for range 1 {
		for _, host := range []string{"transport.synthetic.invalid", "nxdomain.synthetic.invalid", "127.0.0.1", "::1"} {
			t.Run(host, func(t *testing.T) {
				calls := &atomic.Int32{}
				lookup := func(_ context.Context, h string) ([]netip.Addr, error) {
					calls.Add(1)
					if h == "transport.synthetic.invalid" {
						return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
					}
					return nil, &net.DNSError{Name: h, Err: "no such host", IsNotFound: true}
				}
				ctx := underlay.WithBootstrap(underlay.WithFactory(context.Background(), underlay.New()), lookup)
				in, n, c := phase33Intent(t, "vless", "packet-up")
				bind := "127.0.0.1"
				if host == "::1" {
					bind = "::1"
				}
				h, ep := startMKCP(t, ctx, "vless", in, bind)
				defer h.Close(ctx)
				n.Endpoint = ep
				n.Endpoint.Host = host
				d := sharedBuild(t, ctx, n, c)
				defer d.Close()
				target := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
				admission, cancel := context.WithTimeout(ctx, 3*time.Second)
				defer cancel()
				stream, e := d.DialContext(admission, target)
				if host == "nxdomain.synthetic.invalid" {
					if e == nil {
						stream.Close()
						t.Fatal("NXDOMAIN bypassed")
					}
					if calls.Load() != 1 {
						t.Fatal("managed lookup not used", calls.Load())
					}
					return
				}
				if e != nil {
					t.Fatal(e)
				}
				defer stream.Close()
				stream.SetDeadline(time.Now().Add(3 * time.Second))
				if _, e = stream.Write([]byte("dns")); e != nil {
					t.Fatal(e)
				}
				b := make([]byte, 3)
				if _, e = io.ReadFull(stream, b); e != nil || string(b) != "dns" {
					t.Fatal(string(b), e)
				}
				want := int32(0)
				if host == "transport.synthetic.invalid" {
					want = 1
				}
				if calls.Load() != want {
					t.Fatal("literal resolution or managed lookup mismatch", calls.Load(), want)
				}
			})
		}
	}
}

func TestPhase33EncryptionHalfCloseBoundary(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	in, n, credential := phase33Intent(t, "vless", "stream-one")
	public := phase32Enable(t, &in)
	n.Options.Data, _ = json.Marshal(vl.ClientOptions{Security: vl.TLS, Flow: vl.NoFlow, PacketEncoding: "xudp", Encryption: public})
	h, endpoint := startMKCP(t, ctx, "vless", in, "127.0.0.1")
	defer h.Close(ctx)
	n.Endpoint = endpoint
	d := sharedBuild(t, ctx, n, credential)
	defer d.Close()
	c, err := d.DialContext(ctx, netaddrEndpoint(vlessEcho(t, nil).Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = c.(interface{ CloseWrite() error }).CloseWrite(); err != io.ErrClosedPipe {
		t.Fatal("frozen XHTTP has no half-close contract", err)
	}
	if err = phaseExchange(c, []byte("unsupported half-close does not damage stream")); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if _, err = c.Read(make([]byte, 1)); err == nil {
		t.Fatal("full close retained reader")
	}
}

func TestPhase33EncryptionUDPDestinationsAndShutdown(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	in, n, credential := phase33Intent(t, "vless", "packet-up")
	public := phase32Enable(t, &in)
	n.Options.Data, _ = json.Marshal(vl.ClientOptions{Encryption: public, Security: vl.TLS, Flow: vl.NoFlow, PacketEncoding: "xudp"})
	h, endpoint := startMKCP(t, ctx, "vless", in, "127.0.0.1")
	defer h.Close(ctx)
	n.Endpoint = endpoint
	d := sharedBuild(t, ctx, n, credential)
	defer d.Close()
	ipv4 := trojanUDP(t)
	ipv6, e := net.ListenPacket("udp", "[::]:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ipv6.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			count, a, e := ipv6.ReadFrom(b)
			if e != nil {
				return
			}
			_, _ = ipv6.WriteTo(b[:count], a)
		}
	}()
	ipv6Endpoint := netaddrEndpoint(ipv6.LocalAddr())
	ipv6Endpoint.Host = "::1"
	hostname := ipv6Endpoint
	hostname.Host = "localhost"
	for _, dst := range []access.Endpoint{ipv4, ipv6Endpoint, hostname} {
		t.Run(dst.Host, func(t *testing.T) {
			for range 2 {
				p, e := d.(ports.ClientPacketDialer).ListenPacket(ctx, dst)
				if e != nil {
					t.Fatal(e)
				}
				p.SetDeadline(time.Now().Add(3 * time.Second))
				for _, size := range []int{1, 31, 8192, 16000} {
					body := bytes.Repeat([]byte{byte(size)}, size)
					if _, e = p.WriteTo(body, netaddr.UDP(dst)); e != nil {
						t.Fatal(e)
					}
					b := make([]byte, 20000)
					count, _, e := p.ReadFrom(b)
					if e != nil || !bytes.Equal(b[:count], body) {
						t.Fatal("packet boundary/integrity", size, e)
					}
				}
				p.Close()
			}
		})
	}
	// A pending unauthenticated encryption handshake and an active connection are
	// both owned by runtime shutdown; no encrypted session may outlive it.
	pending, e := d.(*vlessDialer).transport.DialContext(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer pending.Close()
	active, e := d.DialContext(ctx, netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr()))
	if e != nil {
		t.Fatal(e)
	}
	defer active.Close()
	if e = phaseExchange(active, []byte("active encrypted session")); e != nil {
		t.Fatal(e)
	}
	if e = h.Close(ctx); e != nil {
		t.Fatal(e)
	}
	for _, c := range []net.Conn{pending, active} {
		c.SetReadDeadline(time.Now().Add(time.Second))
		_, e = c.Read(make([]byte, 1))
		if e == nil {
			t.Fatal("shutdown left connection open")
		}
	}
	if h.Stats().Active != 0 {
		t.Fatal("orphan runtime session")
	}
}

func TestPhase33MultiUserIsolation(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	for _, protocol := range []string{"vless", "vmess", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			in, n, credential := phase33Intent(t, protocol, "stream-one")
			if len(in.Credentials) < 2 {
				t.Fatal("multi-user fixture requires two users")
			}
			h, endpoint := startMKCP(t, ctx, protocol, in, "127.0.0.1")
			defer h.Close(ctx)
			n.Endpoint = endpoint
			a := sharedBuild(t, ctx, n, credential)
			defer a.Close()
			second := in.Credentials[1]
			second.ID = n.CredentialID
			second.OwnerAccountID = nil
			second.OwnerNodeID = &n.ID
			b := sharedBuild(t, ctx, n, second)
			defer b.Close()
			target := netaddrEndpoint(vlessEcho(t, nil).Addr())
			ca, e := a.DialContext(ctx, target)
			if e != nil {
				t.Fatal(e)
			}
			defer ca.Close()
			cb, e := b.DialContext(ctx, target)
			if e != nil {
				t.Fatal(e)
			}
			defer cb.Close()
			if e = phaseExchange(ca, []byte("first-user")); e != nil {
				t.Fatal(e)
			}
			if e = phaseExchange(cb, []byte("second-user")); e != nil {
				t.Fatal(e)
			}
			a.Close()
			if e = phaseExchange(cb, []byte("second-user-survives")); e != nil {
				t.Fatal(e)
			}
		})
	}
}
