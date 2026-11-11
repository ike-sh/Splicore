package native

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/address"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/vmess"
	"github.com/ike-sh/Splicore/internal/splicore/tlsconfig"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// External binaries are optional test peers, never production runtime. The
// runner supplies pinned binaries and an exclusive external evidence directory.
func TestVMessExternalInterop(t *testing.T) {
	peers, root := os.Getenv("SPLICORE_VM_PEERS"), os.Getenv("SPLICORE_VM_INTEROP")
	if peers == "" || root == "" {
		t.Skip("external pinned VMess peers not configured")
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	tcpListener := vmessTCP(t, "[::]:0")
	tcp := netaddrEndpoint(tcpListener.Addr())
	udpListener, err := net.ListenPacket("udp", "[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	udp := netaddrEndpoint(udpListener.LocalAddr())
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65535)
		for {
			n, a, err := udpListener.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = udpListener.WriteTo(b[:n], a)
		}
	}()
	t.Cleanup(func() { _ = udpListener.Close(); <-done })
	for _, tls := range []bool{false, true} {
		for _, security := range []string{"auto", "aes-128-gcm", "chacha20-poly1305", "none"} {
			for _, peer := range []string{"xray-core", "sing-box", "mihomo"} {
				for _, direction := range []string{"client", "server"} {
					if peer == "mihomo" && direction == "server" {
						continue
					}
					name := fmt.Sprintf("%s-%s-%s-tls%t", peer, direction, security, tls)
					t.Run(name, func(t *testing.T) {
						in := vmessIntent(t, tls)
						n, c := vmessNode(t, in, 0, security)
						id := c.Payload.(access.UUIDPayload).UUID.Reveal()
						s, _ := module.Decode(in.Inbound.Settings.Data)
						var d ports.ClientDialer
						var socks access.Endpoint
						if direction == "client" {
							prepared, err := NewVMessCompiler().Compile(ctx, in)
							if err != nil {
								t.Fatal(err)
							}
							h := prepared.(*vmessHandle)
							if h.Start(ctx) != nil {
								t.Fatal("server start")
							}
							h.Activate()
							defer h.Close(ctx)
							l, err := net.Listen("tcp", "127.0.0.1:0")
							if err != nil {
								t.Fatal(err)
							}
							socks = netaddrEndpoint(l.Addr())
							_ = l.Close()
						} else {
							d, err = (VMessOutboundFactory{}).Build(ctx, n, c)
							if err != nil {
								t.Fatal(err)
							}
							defer d.Close()
						}
						config := vmessPeerConfig(peer, direction, id, security, n.Endpoint, socks, s)
						controller := ""
						if peer == "mihomo" {
							l, e := net.Listen("tcp", "127.0.0.1:0")
							if e != nil {
								t.Fatal(e)
							}
							controller = "http://" + l.Addr().String()
							_ = l.Close()
							config.(map[string]any)["external-controller"] = strings.TrimPrefix(controller, "http://")
						}
						file := filepath.Join(root, name+".json")
						b, _ := json.MarshalIndent(config, "", "  ")
						if err := os.WriteFile(file, b, 0600); err != nil {
							t.Fatal(err)
						}
						log, err := os.OpenFile(filepath.Join(root, name+".log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
						if err != nil {
							t.Fatal(err)
						}
						defer log.Close()
						args := []string{"run", "-config", file}
						if peer == "sing-box" {
							args = []string{"run", "-c", file}
						}
						if peer == "mihomo" {
							args = []string{"-f", file, "-d", root}
						}
						cmd := exec.Command(filepath.Join(peers, peer), args...)
						if peer == "xray-core" {
							cmd.Env = append(os.Environ(), "XRAY_CONE_DISABLED=true")
						}
						cmd.Stdout = log
						cmd.Stderr = log
						if err := cmd.Start(); err != nil {
							t.Fatal(err)
						}
						exit := make(chan error, 1)
						go func() { exit <- cmd.Wait() }()
						defer func() { _ = cmd.Process.Kill(); <-exit }()
						endpoint := n.Endpoint
						if direction == "client" {
							endpoint = socks
						}
						ready := false
						for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
							conn, err := net.DialTimeout("tcp", netaddr.TCP(endpoint).String(), 50*time.Millisecond)
							if err == nil {
								_ = conn.Close()
								ready = true
								break
							}
							select {
							case err := <-exit:
								exit <- err
								t.Fatal("peer startup", err)
							default:
							}
							time.Sleep(10 * time.Millisecond)
						}
						if !ready {
							t.Fatal("peer did not listen")
						}
						if peer == "mihomo" {
							client := http.Client{Timeout: time.Second}
							if err := vmessMihomoReady(&client, controller, file); err != nil {
								t.Fatal(err)
							}
						}
						for _, host := range []string{"127.0.0.1", "localhost", "::1"} {
							tcp.Host = host
							udp.Host = host
							t.Run(host, func(t *testing.T) {
								if direction == "server" {
									vmessTransfer(t, d, tcp, udp, 131071)
								} else {
									vmessSOCKSTransfer(t, socks, tcp, udp)
								}
							})
						}
						if !t.Failed() {
							t.Logf("peer=%s direction=%s transport_tls=%t security=%s targets=IPv4/domain/IPv6 TCP_bytes=393213 UDP_request_reply=12 result=PASS", peer, direction, tls, security)
						}
					})
				}
			}
		}
	}
}

// Rules are published before Mihomo admits ordinary TCP sessions. A completed
// controller configuration transaction synchronizes with startup application;
// it sends no VMess traffic and never retries a failed business connection.
func vmessMihomoReady(client *http.Client, controller, configPath string) error {
	loaded := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		resp, err := client.Get(controller + "/rules")
		if err == nil {
			var state struct {
				Rules []struct{ Type, Proxy string } `json:"rules"`
			}
			err = json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&state)
			_ = resp.Body.Close()
			if err == nil && resp.StatusCode == http.StatusOK && len(state.Rules) == 1 && state.Rules[0].Type == "Match" && state.Rules[0].Proxy == "vmess-peer" {
				loaded = true
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !loaded {
		return fmt.Errorf("Mihomo rule configuration not ready")
	}
	body, err := json.Marshal(struct {
		Path string `json:"path"`
	}{Path: configPath})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut, controller+"/configs?force=true", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if _, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 65536)); err != nil {
		return err
	}
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("Mihomo configuration transaction failed: status %d", resp.StatusCode)
	}
	return nil
}

func vmessPeerConfig(peer, direction, id, security string, server, socks access.Endpoint, s module.Settings) any {
	if peer == "xray-core" {
		stream := map[string]any{"network": "tcp", "security": "none"}
		if s.TLS != nil {
			stream["security"] = "tls"
			ts := map[string]any{"serverName": s.TLS.ServerName}
			if direction == "server" {
				ts["certificates"] = []any{map[string]any{"certificateFile": s.TLS.CertificateFile, "keyFile": s.TLS.PrivateKeyFile}}
			} else {
				ts["certificates"] = []any{map[string]any{"usage": "verify", "certificate": strings.Split(strings.TrimSpace(s.TLS.CACertificate), "\n")}}
			}
			stream["tlsSettings"] = ts
		}
		if direction == "server" {
			return map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": server.Port, "protocol": "vmess", "settings": map[string]any{"clients": []any{map[string]any{"id": id, "alterId": 0}}}, "streamSettings": stream}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}
		}
		return map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": socks.Port, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": true}}}, "outbounds": []any{map[string]any{"protocol": "vmess", "settings": map[string]any{"vnext": []any{map[string]any{"address": server.Host, "port": server.Port, "users": []any{map[string]any{"id": id, "alterId": 0, "security": security}}}}}, "streamSettings": stream, "mux": map[string]any{"enabled": false}}}}
	}
	if peer == "sing-box" {
		v := map[string]any{"type": "vmess"}
		if direction == "server" {
			v["listen"], v["listen_port"], v["users"] = "127.0.0.1", server.Port, []any{map[string]any{"uuid": id, "alterId": 0}}
		} else {
			v["server"], v["server_port"], v["uuid"], v["security"], v["alter_id"] = server.Host, server.Port, id, security, 0
		}
		if s.TLS != nil {
			tls := map[string]any{"enabled": true, "server_name": s.TLS.ServerName}
			if direction == "server" {
				tls["certificate_path"], tls["key_path"] = s.TLS.CertificateFile, s.TLS.PrivateKeyFile
			} else {
				tls["certificate"] = []string{s.TLS.CACertificate}
			}
			v["tls"] = tls
		}
		if direction == "server" {
			return map[string]any{"log": map[string]any{"level": "warn"}, "inbounds": []any{v}, "outbounds": []any{map[string]any{"type": "direct"}}}
		}
		return map[string]any{"log": map[string]any{"level": "warn"}, "inbounds": []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": socks.Port}}, "outbounds": []any{v}}
	}
	v := map[string]any{"type": "vmess", "name": "vmess-peer", "server": server.Host, "port": server.Port, "uuid": id, "alterId": 0, "cipher": security, "network": "tcp", "udp": true, "tls": s.TLS != nil}
	if s.TLS != nil {
		pin, _ := tlsconfig.CAFingerprint(s.TLS.CACertificate)
		v["servername"], v["fingerprint"] = s.TLS.ServerName, pin
	}
	return map[string]any{"socks-port": socks.Port, "bind-address": "127.0.0.1", "allow-lan": false, "ipv6": true, "mode": "rule", "log-level": "warning", "proxies": []any{v}, "rules": []string{"MATCH,vmess-peer"}}
}
func vmessSOCKSOpen(t *testing.T, proxy, target access.Endpoint, packet bool) (net.Conn, access.Endpoint) {
	t.Helper()
	c, err := net.DialTimeout("tcp", netaddr.TCP(proxy).String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var greeting [2]byte
	if _, err = io.ReadFull(c, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		t.Fatal("SOCKS greeting", err)
	}
	command := byte(1)
	if packet {
		command = 3
		target = access.Endpoint{Host: "0.0.0.0", Port: 0}
	}
	encoded, err := address.MarshalSOCKS(target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Write(append([]byte{5, command, 0}, encoded...)); err != nil {
		t.Fatal(err)
	}
	var head [3]byte
	if _, err = io.ReadFull(c, head[:]); err != nil || head != [3]byte{5, 0, 0} {
		t.Fatal("SOCKS response", err)
	}
	bound, err := address.ReadSOCKS(c)
	if err != nil {
		t.Fatal(err)
	}
	if bound.Host == "0.0.0.0" || bound.Host == "::" {
		bound.Host = proxy.Host
	}
	return c, bound
}
func vmessSOCKSTransfer(t *testing.T, proxy, tcp, udp access.Endpoint) {
	t.Helper()
	c, _ := vmessSOCKSOpen(t, proxy, tcp, false)
	defer c.Close()
	payload := bytes.Repeat([]byte{29}, 131071)
	done := make(chan error, 1)
	go func() { _, err := c.Write(payload); done <- err }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal("external TCP", err)
	}
	if err := <-done; err != nil || !bytes.Equal(got, payload) {
		t.Fatal("external TCP integrity", err)
	}
	_ = c.Close()
	control, bound := vmessSOCKSOpen(t, proxy, udp, true)
	raw, err := net.Dial("udp", netaddr.UDP(bound).String())
	if err != nil {
		_ = control.Close()
		t.Fatal(err)
	}
	p := testfixture.SOCKSPacket(raw, control)
	defer p.Close()
	_ = p.SetDeadline(time.Now().Add(5 * time.Second))
	for _, size := range []int{1, 128, 1000, 1200} {
		v := bytes.Repeat([]byte{47}, size)
		if _, err = p.WriteTo(v, netaddr.UDP(udp)); err != nil {
			t.Fatal("external UDP write", err)
		}
		b := make([]byte, 65535)
		n, _, err := p.ReadFrom(b)
		if err != nil || !bytes.Equal(v, b[:n]) {
			t.Fatal("external UDP reply", size, err)
		}
	}
}
