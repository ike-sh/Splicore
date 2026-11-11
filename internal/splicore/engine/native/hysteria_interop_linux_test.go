//go:build linux

package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	hm "github.com/ike-sh/Splicore/internal/splicore/protocol/hysteria2"
	ht "github.com/ike-sh/Splicore/internal/splicore/streamtransport/hysteria"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func hyOwnedAddress(pid int, network string, want int, host string) (string, bool) {
	fds, e := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if e != nil {
		return "", false
	}
	inodes := map[string]bool{}
	for _, fd := range fds {
		link, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
		if strings.HasPrefix(link, "socket:[") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = true
		}
	}
	for _, table := range []string{network, network + "6"} {
		b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/net/%s", pid, table))
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 10 || !inodes[f[9]] || network == "tcp" && f[3] != "0A" {
				continue
			}
			a := strings.Split(f[1], ":")
			if len(a) != 2 {
				continue
			}
			if network == "udp" && want == 0 && strings.Trim(a[0], "0") == "" {
				continue
			}
			port, e := strconv.ParseInt(a[1], 16, 32)
			if e == nil && port > 0 && (want == 0 || int(port) == want) {
				return net.JoinHostPort(host, strconv.Itoa(int(port))), true
			}
		}
	}
	return "", false
}
func hyStart(t *testing.T, reference, kind, dir, role string, doc any, network string, want int, host string) string {
	t.Helper()
	path := filepath.Join(dir, role+"-config.json")
	mkcpJSON(t, path, doc)
	log, e := os.Create(filepath.Join(dir, role+"-reference.log"))
	if e != nil {
		t.Fatal(e)
	}
	args := []string{role, "-c", path, "--disable-update-check"}
	if kind == "xray" {
		args = []string{"run", "-config", path}
	}
	cmd := exec.Command(reference, args...)
	cmd.Stdout = log
	cmd.Stderr = log
	if e = cmd.Start(); e != nil {
		log.Close()
		t.Fatal(e)
	}
	mkcpJSON(t, filepath.Join(dir, role+"-pid.json"), map[string]any{"pid": cmd.Process.Pid})
	done := make(chan error, 1)
	go func() { done <- cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGTERM)
		forced := false
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			forced = true
			cmd.Process.Kill()
			<-done
		}
		log.Close()
		mkcpJSON(t, filepath.Join(dir, role+"-cleanup.json"), map[string]any{"pid": cmd.Process.Pid, "wait_joined": true, "forced_kill": forced, "exit_code": cmd.ProcessState.ExitCode()})
	})
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if a, ok := hyOwnedAddress(cmd.Process.Pid, network, want, host); ok {
			return a
		}
		select {
		case e := <-done:
			t.Fatalf("reference exited before bind: %v; see %s", e, dir)
		case <-timeout.C:
			t.Fatalf("reference bind timed out: %s", dir)
		case <-tick.C:
		}
	}
}
func hyAddress(dst access.Endpoint) []byte {
	var out []byte
	ip := net.ParseIP(dst.Host)
	if ip == nil {
		out = append([]byte{3, byte(len(dst.Host))}, dst.Host...)
	} else if v := ip.To4(); v != nil {
		out = append([]byte{1}, v...)
	} else {
		out = append([]byte{4}, ip.To16()...)
	}
	return binary.BigEndian.AppendUint16(out, dst.Port)
}
func hyReferencePID(t *testing.T, dir, role string) int {
	t.Helper()
	b, e := os.ReadFile(filepath.Join(dir, role+"-pid.json"))
	var v struct{ PID int }
	if e != nil || json.Unmarshal(b, &v) != nil {
		t.Fatal(e)
	}
	return v.PID
}
func hySocks(t *testing.T, address string, command byte, dst access.Endpoint) (net.Conn, *net.UDPAddr) {
	t.Helper()
	c, e := net.DialTimeout("tcp", address, 5*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(15 * time.Second))
	fail := func(e error) { c.Close(); t.Fatal(e) }
	if _, e = c.Write([]byte{5, 1, 0}); e != nil {
		fail(e)
	}
	var method [2]byte
	if _, e = io.ReadFull(c, method[:]); e != nil || method != [2]byte{5, 0} {
		fail(fmt.Errorf("SOCKS method %v %v", method, e))
	}
	req := append([]byte{5, command, 0}, hyAddress(dst)...)
	if _, e = c.Write(req); e != nil {
		fail(e)
	}
	var head [4]byte
	if _, e = io.ReadFull(c, head[:]); e != nil || head[0] != 5 || head[1] != 0 {
		fail(fmt.Errorf("SOCKS reply %v %v", head, e))
	}
	n := 4
	if head[3] == 4 {
		n = 16
	} else if head[3] == 3 {
		var size [1]byte
		io.ReadFull(c, size[:])
		n = int(size[0])
	} else if head[3] != 1 {
		fail(fmt.Errorf("SOCKS address"))
	}
	b := make([]byte, n+2)
	if _, e = io.ReadFull(c, b); e != nil {
		fail(e)
	}
	ip := net.IP(b[:n])
	if head[3] == 3 {
		ip = net.ParseIP(string(b[:n]))
	}
	if ip == nil || ip.IsUnspecified() {
		host, _, _ := net.SplitHostPort(address)
		ip = net.ParseIP(host)
	}
	return c, &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(b[n:]))}
}
func hyUDP(t *testing.T, write func([]byte) error, read func([]byte) (int, error), limits ...int) []map[string]any {
	t.Helper()
	var rows []map[string]any
	maximum := 4096
	if len(limits) > 0 {
		maximum = limits[0]
	}
	for _, size := range []int{1, 900, maximum} {
		want := make([]byte, size)
		for i := range want {
			want[i] = byte(i*37 + 19)
		}
		if e := write(want); e != nil {
			t.Fatal(e)
		}
		got := make([]byte, 8192)
		n, e := read(got)
		if e != nil || !bytes.Equal(got[:n], want) {
			t.Fatalf("UDP %d integrity: %v n=%d", size, e, n)
		}
		rows = append(rows, map[string]any{"profile": "UDP_PAYLOAD", "bytes": size, "source_sha256": hyBytesHash(want), "destination_sha256": hyBytesHash(got[:n]), "payload_integrity": "PASS"})
	}
	return rows
}
func hyBytesHash(b []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
func secretValue(s string) secret.Value { return secret.New(s) }
func netaddrString(t *testing.T, s string) access.Endpoint {
	t.Helper()
	host, port, e := net.SplitHostPort(s)
	if e != nil {
		t.Fatal(e)
	}
	n, e := strconv.ParseUint(port, 10, 16)
	if e != nil {
		t.Fatal(e)
	}
	return access.Endpoint{Host: host, Port: uint16(n)}
}
func TestNativeHysteriaPinnedReferences(t *testing.T) {
	root := os.Getenv("SPLICORE_HYSTERIA_EVIDENCE")
	if root == "" {
		t.Skip("explicit pinned local reference campaign required")
	}
	exe, _ := os.Executable()
	var binding map[string]any
	if path := os.Getenv("SPLICORE_HYSTERIA_BINDING"); path != "" {
		b, e := os.ReadFile(path)
		if e != nil || json.Unmarshal(b, &binding) != nil {
			t.Fatal("binding", e)
		}
		if binding["validation_binary_sha256"] != mkcpSHA(t, exe) {
			t.Fatal("stale candidate binary")
		}
	}
	for kindIndex, kind := range []string{"hysteria", "xray"} {
		ref := os.Getenv("SPLICORE_HYSTERIA_REFERENCE")
		expected := "907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691"
		tag := "app/v2.13.0"
		commit := "ca8fbd874fd6ca82413948de6dc5924405e103e1"
		if kind == "xray" {
			ref = os.Getenv("SPLICORE_HYSTERIA_XRAY")
			expected = "4cca4de3ab8c16b3803a70e9ebe0570d2a72480c716d89aa91603ec568bf0f44"
			tag = "v26.10.10"
			commit = "701af60772cda123492f86e383e1fdba066614a9"
		}
		if ref == "" || mkcpSHA(t, ref) != expected {
			t.Fatal("pinned reference identity", kind)
		}
		for profileIndex, host := range []string{"127.0.0.1", "::1"} {
			for directionIndex, direction := range []string{"REFERENCE_TO_SPLICORE", "SPLICORE_TO_REFERENCE"} {
				variants := []string{"base"}
				if profileIndex == 0 {
					variants = append(variants, "bbr", "brutal", "inverse", "fallback")
					if kind == "xray" {
						variants = append(variants, "force")
					}
					variants = append(variants, "domain")
				}
				for variantIndex, variant := range variants {
					name := kind + "-" + direction + "-" + strconv.Itoa(profileIndex)
					if variant != "base" {
						name += "-" + variant
					}
					t.Run(name, func(t *testing.T) {
						dir := filepath.Join(root, name)
						os.MkdirAll(dir, 0700)
						ctx := underlay.WithFactory(context.Background(), underlay.New())
						material := testkit.TLS(t)
						cert, _ := os.ReadFile(material.CertificateFile)
						key, _ := os.ReadFile(material.PrivateKeyFile)
						certPath := filepath.Join(dir, "cert.pem")
						keyPath := filepath.Join(dir, "key.pem")
						caPath := filepath.Join(dir, "ca.pem")
						os.WriteFile(certPath, cert, 0600)
						os.WriteFile(keyPath, key, 0600)
						os.WriteFile(caPath, []byte(material.CACertificate), 0600)
						l, e := net.Listen("tcp", net.JoinHostPort(host, "0"))
						if e != nil {
							t.Fatal(e)
						}
						target := netaddrEndpoint(l.Addr())
						tcpDone := make(chan struct{})
						go func() {
							defer close(tcpDone)
							for {
								c, e := l.Accept()
								if e != nil {
									return
								}
								go func() { defer c.Close(); io.Copy(c, c) }()
							}
						}()
						t.Cleanup(func() { l.Close(); <-tcpDone })
						udp, e := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
						if e != nil {
							t.Fatal(e)
						}
						udpDone := make(chan struct{})
						go func() {
							defer close(udpDone)
							b := make([]byte, 8192)
							for {
								n, a, e := udp.ReadFrom(b)
								if e != nil {
									return
								}
								udp.WriteTo(b[:n], a)
							}
						}()
						t.Cleanup(func() { udp.Close(); <-udpDone })
						udpTarget := netaddrEndpoint(udp.LocalAddr())
						if variant == "domain" {
							target.Host = "localhost"
							udpTarget.Host = "localhost"
						}
						password := "SyntheticHysteriaPhase28Password"
						var states []ht.CongestionState
						var serverAddress string
						var referenceClientQualification map[string]any
						spq, refq := hyProfileCongestion(variant, directionIndex)
						if variant == "fallback" && kind == "xray" {
							spq.BrutalUp = "0"
						}

						var rows []map[string]any
						if directionIndex == 0 {
							in := testfixture.MieruIntentAt(t, "udp", access.Endpoint{Host: host, Port: 1})
							in.Inbound.Protocol = hm.Key()
							in.Inbound.Settings.Data, _ = json.Marshal(hm.Settings{TLS: material, StreamTransport: &cfg.Config{Kind: "hysteria", Hysteria: &cfg.Hysteria{Version: 2, UDPIdleTimeout: 2, QUIC: spq}}})
							for i := range in.Credentials {
								in.Credentials[i].Payload = access.PasswordPayload{Password: secretValue(password + strconv.Itoa(i))}
								in.Credentials[i].Kind = access.Password
							}
							prepared, e := (Hysteria2Compiler{}).Compile(ctx, in)
							if e != nil {
								t.Fatal(e)
							}
							h := prepared.(*hysteria2Handle)
							h.endpoint.Port = 0
							if e = h.Start(ctx); e != nil {
								t.Fatal(e)
							}
							h.Activate()
							t.Cleanup(func() { h.Close(context.Background()) })
							remote := netaddrEndpoint(h.server.Addr())
							serverAddress = h.server.Addr().String()
							password += "0"
							var doc any
							want := 0
							if kind == "hysteria" {
								doc = map[string]any{"server": h.server.Addr().String(), "auth": password, "tls": map[string]any{"sni": material.ServerName, "ca": caPath}, "socks5": map[string]any{"listen": net.JoinHostPort(host, "0")}, "udpForwarding": []any{map[string]any{"listen": net.JoinHostPort(host, "0"), "remote": net.JoinHostPort(udpTarget.Host, strconv.Itoa(int(udpTarget.Port)))}}}
							} else {
								want = 42000 + kindIndex*100 + profileIndex*10 + variantIndex
								doc = map[string]any{"log": map[string]any{"loglevel": "debug"}, "inbounds": []any{map[string]any{"listen": host, "port": want, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": true}}}, "outbounds": []any{map[string]any{"protocol": "hysteria", "settings": map[string]any{"version": 2, "address": remote.Host, "port": remote.Port}, "streamSettings": map[string]any{"network": "hysteria", "security": "tls", "hysteriaSettings": map[string]any{"version": 2, "auth": password}, "tlsSettings": map[string]any{"serverName": material.ServerName, "alpn": []string{"h3"}, "certificates": []any{map[string]any{"certificateFile": caPath, "usage": "verify"}}}}}}}
							}
							hyConfigureCongestion(doc, kind, "client", refq)
							socks := hyStart(t, ref, kind, dir, "client", doc, "tcp", want, host)
							rows = append(rows, mkcpPayloadRows(t, func(dst access.Endpoint) net.Conn { c, _ := hySocks(t, socks, 1, dst); return c }, target, 1200, false, 15*time.Second)...)
							for range 2 {
								if kind == "hysteria" {
									pidReady := false
									var forward string
									// The reference's retained forwarding socket is selected
									// from its recorded PID, never by probe/close/rebind.
									forward, pidReady = hyOwnedAddress(hyReferencePID(t, dir, "client"), "udp", 0, host)
									if !pidReady {
										t.Fatal("forwarding socket absent")
									}
									c, e := net.Dial("udp", forward)
									if e != nil {
										t.Fatal(e)
									}
									c.SetDeadline(time.Now().Add(10 * time.Second))
									rows = append(rows, hyUDP(t, func(b []byte) error { _, e := c.Write(b); return e }, c.Read, 4048)...)
									c.Close()
									continue
								}
								control, relay := hySocks(t, socks, 3, access.Endpoint{Host: host, Port: 0})
								p, e := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
								if e != nil {
									t.Fatal(e)
								}
								p.SetDeadline(time.Now().Add(10 * time.Second))
								header := append([]byte{0, 0, 0}, hyAddress(udpTarget)...)
								rows = append(rows, hyUDP(t, func(b []byte) error { _, e := p.WriteTo(append(bytes.Clone(header), b...), relay); return e }, func(b []byte) (int, error) {
									raw := make([]byte, 8192)
									n, _, e := p.ReadFrom(raw)
									if e != nil {
										return 0, e
									}
									offset := 10
									if n > 4 && raw[3] == 4 {
										offset = 22
									} else if n > 5 && raw[3] == 3 {
										offset = 7 + int(raw[4])
									}
									if n < offset {
										return 0, io.ErrUnexpectedEOF
									}
									return copy(b, raw[offset:n]), nil
								})...)
								p.Close()
								control.Close()
							}
							if variant == "base" && profileIndex == 0 {
								referenceClientQualification = hyClientAuthAndConcurrency(t, ref, kind, dir, doc, socks, h, target, udpTarget)
							}
							states = h.server.Congestion()
						} else {
							want := 0
							var doc any
							if kind == "hysteria" {
								doc = map[string]any{"listen": net.JoinHostPort(host, "0"), "tls": map[string]any{"cert": certPath, "key": keyPath}, "auth": map[string]any{"type": "password", "password": password}}
							} else {
								want = 42200 + profileIndex*10 + variantIndex
								doc = map[string]any{"log": map[string]any{"loglevel": "debug"}, "inbounds": []any{map[string]any{"listen": host, "port": want, "protocol": "hysteria", "settings": map[string]any{"version": 2, "users": []any{map[string]any{"auth": password}}}, "streamSettings": map[string]any{"network": "hysteria", "security": "tls", "hysteriaSettings": map[string]any{"version": 2, "udpIdleTimeout": 2}, "tlsSettings": map[string]any{"alpn": []string{"h3"}, "certificates": []any{map[string]any{"certificateFile": certPath, "keyFile": keyPath}}}}}}, "outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32", "::1/128"}}}}}}}
							}
							hyConfigureCongestion(doc, kind, "server", refq)
							remote := hyStart(t, ref, kind, dir, "server", doc, "udp", want, host)
							serverAddress = remote
							endpoint := netaddrString(t, remote)
							nid, _ := identity.NewID()
							cid, _ := identity.NewID()
							credential := access.Credential{ID: cid, OwnerNodeID: &nid, Kind: access.Password, Schema: 1, State: "active", Payload: access.PasswordPayload{Password: secretValue(password)}, Stamp: identity.NewStamp(time.Now())}
							node := client.RemoteNode{ID: nid, Name: "controlled", Protocol: hm.Key(), Endpoint: endpoint, CredentialID: cid, Transport: client.Transport{Kind: "hysteria", Hysteria: &cfg.Hysteria{Version: 2, QUIC: spq}}, Security: client.Security{Kind: "tls", TLS: access.ClientTLS{Enabled: true, Trust: "explicit_ca", ServerName: material.ServerName, CACertificate: material.CACertificate, ALPN: []string{"h3"}}}, Options: client.Options{Schema: 1, Data: []byte("{}")}}
							dialer, e := (Hysteria2OutboundFactory{}).Build(ctx, node, credential)
							if e != nil {
								t.Fatal(e)
							}
							defer dialer.Close()
							rows = append(rows, mkcpPayloadRows(t, func(dst access.Endpoint) net.Conn {
								c, e := dialer.DialContext(ctx, dst)
								if e != nil {
									t.Fatal(e)
								}
								return c
							}, target, 1200, false, 15*time.Second)...)
							for range 2 {
								p, e := dialer.(ports.ClientPacketDialer).ListenPacket(ctx, udpTarget)
								if e != nil {
									t.Fatal(e)
								}
								p.SetDeadline(time.Now().Add(10 * time.Second))
								maximum := 4096
								if kind == "hysteria" {
									maximum = 4048
								}
								rows = append(rows, hyUDP(t, func(b []byte) error { _, e := p.WriteTo(b, nil); return e }, func(b []byte) (int, error) { n, _, e := p.ReadFrom(b); return n, e }, maximum)...)
								p.Close()
							}
							states = dialer.(*hysteria2Dialer).client.Congestion()
						}
						hyAssertController(t, spq, states, variant, directionIndex)
						for i, row := range rows {
							network, dst := "tcp", target
							if row["profile"] == "UDP_PAYLOAD" {
								network, dst = "udp", udpTarget
							}
							row["profile_id"], row["check_index"] = name, i
							row["direction"], row["network"] = direction, network
							row["proxy_target"] = net.JoinHostPort(dst.Host, strconv.Itoa(int(dst.Port)))
							row["target_address_type"] = hyTargetType(dst.Host)
						}
						record := map[string]any{"congestion_variant": variant, "congestion_settings": spq, "actual_controllers": states, "auth_identity": "synthetic-user-0", "transport_mode": "specialized Hysteria2/QUIC/TLS1.3/h3", "reference_kind": kind, "reference_tag": tag, "reference_commit": commit, "reference_sha256": expected, "validation_binary_sha256": mkcpSHA(t, exe), "direction": direction, "profile_id": name, "host": host, "result": "PASS", "payloads": rows, "Splicore_ports": "actual owned :0", "reference_port_policy": "official :0; Xray deterministic profile port, one bind, no probe/search/retry"}
						for k, v := range binding {
							record[k] = v
						}
						record["reference_client_auth_concurrency"] = referenceClientQualification
						record["server_address_type"] = hyTargetType(host)
						record["server_address"] = serverAddress
						record["TCP_proxy_target"] = net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port)))
						record["UDP_proxy_target"] = net.JoinHostPort(udpTarget.Host, strconv.Itoa(int(udpTarget.Port)))
						record["TCP_target_address_type"] = hyTargetType(target.Host)
						record["UDP_target_address_type"] = hyTargetType(udpTarget.Host)
						mkcpJSON(t, filepath.Join(dir, "result.json"), record)
					})
				}
			}
		}
	}
}

func hyTargetType(host string) string {
	ip := net.ParseIP(host)
	if ip == nil {
		return "DOMAIN"
	}
	if ip.To4() != nil {
		return "IPv4"
	}
	return "IPv6"
}

func hyProfileCongestion(variant string, direction int) (cfg.QUIC, cfg.QUIC) {
	local, peer := cfg.QUIC{}, cfg.QUIC{}
	switch variant {
	case "base":
		if direction == 0 {
			local = cfg.QUIC{InitialStreamWindow: 1 << 20, MaxStreamWindow: 2 << 20, InitialConnectionWindow: 4 << 20, MaxConnectionWindow: 8 << 20}
		} else {
			local = cfg.QUIC{KeepAlivePeriod: 1, MaxIdleTimeout: 4}
		}
	case "bbr":
		local.Congestion = "bbr"
		peer.Congestion = "bbr"
	case "brutal", "inverse", "force":
		client := cfg.QUIC{Congestion: "brutal", BrutalUp: "20mbps", BrutalDown: "100mbps"}
		server := cfg.QUIC{Congestion: "brutal", BrutalUp: "40mbps", BrutalDown: "1mbps"}
		if variant == "inverse" {
			client.BrutalUp = "1mbps"
			client.BrutalDown = "20mbps"
			server.BrutalUp = "100mbps"
			server.BrutalDown = "40mbps"
		}
		if variant == "force" {
			client.Congestion = "force-brutal"
			server.Congestion = "force-brutal"
		}
		if direction == 0 {
			local = server
			peer = client
		} else {
			local = client
			peer = server
		}
	case "fallback":
		local = cfg.QUIC{Congestion: "brutal", BrutalUp: "20mbps"}
		peer.Congestion = "bbr"
	}
	return local, peer
}
func hyConfigureCongestion(doc any, kind, role string, q cfg.QUIC) {
	if q.Congestion == "" {
		return
	}
	d := doc.(map[string]any)
	if kind == "hysteria" {
		d["congestion"] = map[string]any{"type": "bbr"}
		if q.Congestion == "brutal" {
			d["bandwidth"] = map[string]any{"up": q.BrutalUp, "down": q.BrutalDown}
		}
		if role == "server" && q.Congestion == "bbr" {
			d["ignoreClientBandwidth"] = true
		}
	} else {
		key := "inbounds"
		if role == "client" {
			key = "outbounds"
		}
		stream := d[key].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
		params := map[string]any{"congestion": q.Congestion, "debug": true}
		if q.BrutalUp != "" {
			rate, e := cfg.RateBytes(q.BrutalUp)
			if e != nil {
				panic(e)
			}
			params["brutalUp"] = strconv.FormatUint(rate*8, 10) + "bps"
		}
		if q.BrutalDown != "" {
			rate, e := cfg.RateBytes(q.BrutalDown)
			if e != nil {
				panic(e)
			}
			params["brutalDown"] = strconv.FormatUint(rate*8, 10) + "bps"
		}
		stream["finalmask"] = map[string]any{"quicParams": params}
	}
}
func hyAssertController(t *testing.T, q cfg.QUIC, states []ht.CongestionState, variant string, direction int) {
	t.Helper()
	if len(states) != 1 && !(variant == "base" && direction == 0 && len(states) == 2) {
		t.Fatal("connection reuse/controller identity", states)
	}
	s := states[0]
	wantMode := "reno"
	var wantRate uint64
	switch variant {
	case "bbr", "fallback":
		wantMode = "bbr"
	case "brutal":
		wantMode = "brutal"
		wantRate = 125000
		if direction == 0 {
			wantRate = 5000000
		}
	case "inverse":
		wantMode = "brutal"
		wantRate = 125000
		if direction == 0 {
			wantRate = 2500000
		}
	case "force":
		wantMode = "brutal"
		wantRate = 2500000
		if direction == 0 {
			wantRate = 5000000
		}
	}
	if s.Selected != wantMode || s.EffectiveRateBytesPerSecond != wantRate {
		t.Fatal("reference selection/direction", s, wantMode, wantRate)
	}
	if s.Requested != q.Defaults().Congestion {
		t.Fatal("requested controller", s)
	}
	if s.Selected != "reno" && (s.Controller != "native "+s.Selected || s.Model.Algorithm != s.Selected || s.Model.Sent == 0 || s.Model.Acked == 0) {
		t.Fatal("actual controller inactive", s)
	}
}
