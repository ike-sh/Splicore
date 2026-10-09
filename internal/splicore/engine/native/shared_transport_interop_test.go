package native

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	tm "github.com/ike-sh/Splicore/internal/splicore/protocol/trojan"
	vl "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	vm "github.com/ike-sh/Splicore/internal/splicore/protocol/vmess"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

// Independent peer binaries are optional local test tools, never production
// engines. All endpoints are owned loopback and all credentials are synthetic.
func TestSharedTransportExternalInterop(t *testing.T) {
	peers, root := os.Getenv("SPLICORE_SHARED_PEERS"), os.Getenv("SPLICORE_SHARED_INTEROP")
	if peers == "" || root == "" {
		t.Skip("external local peers not configured")
	}
	if e := os.MkdirAll(root, 0700); e != nil {
		t.Fatal(e)
	}
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	tcp := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	udp := trojanUDP(t)
	for _, protocol := range []string{"vmess", "vless", "trojan"} {
		for _, kind := range []string{"ws", "httpupgrade", "grpc"} {
			for _, peer := range []string{"xray-core", "sing-box"} {
				for _, direction := range []string{"client", "server"} {
					t.Run(protocol+"-"+kind+"-"+peer+"-"+direction, func(t *testing.T) {
						in, n, c := sharedIntent(t, protocol, kind, true)
						if protocol == "vmess" && kind == "grpc" && peer == "sing-box" && direction == "server" {
							// Independent external listener with explicit authority distinct
							// from the shared TLS identity and the loopback endpoint.
							n.Transport.Host = "authority.synthetic.test"
						}
						l, e := net.Listen("tcp", "127.0.0.1:0")
						if e != nil {
							t.Fatal(e)
						}
						socks := netaddrEndpoint(l.Addr())
						l.Close()
						var d ports.ClientDialer
						if direction == "client" {
							h := sharedPrepare(t, ctx, protocol, in)
							if e = h.Start(ctx); e != nil {
								t.Fatal(e)
							}
							h.Activate()
							defer h.Close(ctx)
						} else {
							d = sharedBuild(t, ctx, n, c)
							defer d.Close()
						}
						config := sharedPeerConfig(t, peer, direction, protocol, in, n, c, socks)
						name := protocol + "-" + kind + "-" + peer + "-" + direction
						file := filepath.Join(root, name+".json")
						b, _ := json.MarshalIndent(config, "", "  ")
						if e = os.WriteFile(file, b, 0600); e != nil {
							t.Fatal(e)
						}
						log, e := os.OpenFile(filepath.Join(root, name+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
						if e != nil {
							t.Fatal(e)
						}
						defer log.Close()
						args := []string{"run", "-config", file}
						if peer == "sing-box" {
							args = []string{"run", "-c", file}
						}
						cmd := exec.Command(filepath.Join(peers, peer), args...)
						cmd.Stdout = log
						cmd.Stderr = log
						cmd.Env = append(os.Environ(), "XRAY_CONE_DISABLED=true")
						if e = cmd.Start(); e != nil {
							t.Fatal(e)
						}
						exit := make(chan error, 1)
						go func() { exit <- cmd.Wait() }()
						defer func() { cmd.Process.Kill(); <-exit }()
						endpoint := n.Endpoint
						if direction == "client" {
							endpoint = socks
						}
						ready := false
						until := time.Now().Add(5 * time.Second)
						for time.Now().Before(until) {
							probe, e := net.DialTimeout("tcp", netaddr.TCP(endpoint).String(), 50*time.Millisecond)
							if e == nil {
								probe.Close()
								ready = true
								break
							}
							select {
							case e := <-exit:
								exit <- e
								t.Fatalf("peer failed: %v", e)
							default:
							}
							time.Sleep(5 * time.Millisecond)
						}
						if !ready {
							t.Fatal("local peer did not listen")
						}
						// No retries of business traffic. Only deterministic local startup admission
						// is awaited; the protocol carries payload and reply in both directions.
						if direction == "server" {
							sharedPayload(t, d, tcp, udp)
						} else {
							sharedExternalPayload(t, socks, tcp, udp)
						}
						if !t.Failed() {
							result := map[string]any{"protocol": protocol, "transport": kind, "security": "tls", "peer": peer, "direction": map[string]string{"client": "external client -> Splicore server", "server": "Splicore client -> external server"}[direction], "TCP": "PASS", "UDP": "PASS", "application_reply": true, "synthetic_credentials": true, "result": "PASS"}
							out, _ := json.MarshalIndent(result, "", "  ")
							os.WriteFile(filepath.Join(root, name+".result.json"), out, 0600)
							t.Logf("protocol=%s transport=%s peer=%s Splicore=%s TCP/UDP payload+reply PASS", protocol, kind, peer, direction)
						}
					})
				}
			}
		}
	}
}

// Xray 26.3.27 Trojan rejects a full first application buffer while constructing
// its request ("buffer is full"). Exercise a small request/reply before the large
// sustained stream; no business request is retried and server bytes are unchanged.
func sharedExternalPayload(t *testing.T, proxy, tcp, udp access.Endpoint) {
	t.Helper()
	c, _ := vmessSOCKSOpen(t, proxy, tcp, false)
	defer c.Close()
	first := []byte("synthetic-shared-transport-initial-reply")
	if _, e := c.Write(first); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, len(first))
	if _, e := io.ReadFull(c, b); e != nil || !bytes.Equal(b, first) {
		t.Fatal("initial reply", e)
	}
	payload := bytes.Repeat([]byte{29}, 131071)
	done := make(chan error, 1)
	go func() { _, e := c.Write(payload); done <- e }()
	b = make([]byte, len(payload))
	if _, e := io.ReadFull(c, b); e != nil {
		t.Fatal("sustained reply", e)
	}
	if e := <-done; e != nil || !bytes.Equal(b, payload) {
		t.Fatal("sustained payload", e)
	}
	c.Close()
	control, bound := vmessSOCKSOpen(t, proxy, udp, true)
	raw, e := net.Dial("udp", netaddr.UDP(bound).String())
	if e != nil {
		control.Close()
		t.Fatal(e)
	}
	p := testfixture.SOCKSPacket(raw, control)
	defer p.Close()
	p.SetDeadline(time.Now().Add(5 * time.Second))
	for _, size := range []int{1, 128, 1000, 1200} {
		payload := bytes.Repeat([]byte{47}, size)
		if _, e := p.WriteTo(payload, netaddr.UDP(udp)); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, 65535)
		n, _, e := p.ReadFrom(b)
		if e != nil || !bytes.Equal(payload, b[:n]) {
			t.Fatal("UDP reply", size, e)
		}
	}
}
func sharedPeerConfig(t *testing.T, peer, direction, protocol string, in ports.RuntimeIntent, n client.RemoteNode, credential access.Credential, socks access.Endpoint) map[string]any {
	t.Helper()
	material := vm.Settings{Security: "tls"}
	switch protocol {
	case "vmess":
		material, _ = vm.Decode(in.Inbound.Settings.Data)
	case "vless":
		s, _ := vl.Decode(in.Inbound.Settings.Data)
		material.TLS = s.TLS
	case "trojan":
		s, _ := tm.Decode(in.Inbound.Settings.Data)
		material.TLS = &s.TLS
	}
	key := ""
	if protocol == "trojan" {
		key = credential.Payload.(access.PasswordPayload).Password.Reveal()
	} else {
		key = credential.Payload.(access.UUIDPayload).UUID.Reveal()
	}
	root := vmessPeerConfig(peer, direction, key, "auto", n.Endpoint, socks, material).(map[string]any)
	if peer == "xray-core" {
		root["log"] = map[string]any{"loglevel": "debug"}
	}
	field := "outbounds"
	if direction == "server" {
		field = "inbounds"
	}
	v := root[field].([]any)[0].(map[string]any)
	transport := n.Transport
	if peer == "xray-core" {
		v["protocol"] = protocol
		settings := map[string]any{}
		if direction == "server" {
			user := map[string]any{"id": key}
			if protocol == "trojan" {
				user = map[string]any{"password": key}
			}
			settings["clients"] = []any{user}
			if protocol == "vless" {
				settings["decryption"] = "none"
			}
		}
		if direction == "client" {
			if protocol == "trojan" {
				settings["servers"] = []any{map[string]any{"address": n.Endpoint.Host, "port": n.Endpoint.Port, "password": key}}
			} else {
				user := map[string]any{"id": key}
				if protocol == "vless" {
					user["encryption"] = "none"
				} else {
					user["security"] = "auto"
					user["alterId"] = 0
				}
				settings["vnext"] = []any{map[string]any{"address": n.Endpoint.Host, "port": n.Endpoint.Port, "users": []any{user}}}
			}
		}
		v["settings"] = settings
		stream := v["streamSettings"].(map[string]any)
		stream["network"] = transport.Kind
		options := map[string]any{}
		if transport.Kind == "grpc" {
			options["serviceName"] = transport.Service()
			stream["grpcSettings"] = options
		} else {
			options["path"] = transport.HTTPPath()
			options["host"] = transport.Host
			field := "wsSettings"
			if transport.Kind == "httpupgrade" {
				field = "httpupgradeSettings"
			}
			stream[field] = options
		}
		stream["tlsSettings"].(map[string]any)["alpn"] = []string{"http/1.1"}
		if transport.Kind == "grpc" {
			stream["tlsSettings"].(map[string]any)["alpn"] = []string{"h2"}
		}
	} else {
		v["type"] = protocol
		delete(v, "security")
		delete(v, "alter_id")
		if direction == "server" {
			user := map[string]any{"uuid": key}
			if protocol == "trojan" {
				user = map[string]any{"password": key}
			}
			v["users"] = []any{user}
		} else {
			if protocol == "trojan" {
				delete(v, "uuid")
				v["password"] = key
			} else {
				v["uuid"] = key
				if protocol == "vmess" {
					v["security"] = "auto"
					v["alter_id"] = 0
				}
			}
		}
		tr := map[string]any{"type": transport.Kind}
		if transport.Kind == "grpc" {
			tr["service_name"] = transport.Service()
		} else {
			tr["path"] = transport.HTTPPath()
			if transport.Kind == "ws" {
				if direction == "client" {
					tr["headers"] = map[string]string{"Host": transport.Host}
				}
			} else {
				tr["host"] = transport.Host
			}
		}
		v["transport"] = tr
	}
	return root
}
