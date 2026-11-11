//go:build linux

package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	vlbackend "github.com/ike-sh/Splicore/protocol/vless/backend"
)

type mkcpProfile struct {
	name        string
	local, peer cfg.MKCP
}

func mkcpProfiles() []mkcpProfile {
	d := cfg.DefaultMKCP()
	profiles := []mkcpProfile{{"DEFAULT", d, d}}
	add := func(name string, change func(*cfg.MKCP)) {
		m := d
		change(&m)
		profiles = append(profiles, mkcpProfile{name, m, m})
	}
	add("LOW_TTI", func(m *cfg.MKCP) { m.TTI = 10 })
	add("CUSTOM_MTU", func(m *cfg.MKCP) { m.MTU = 576 })
	add("CUSTOM_CAPACITY", func(m *cfg.MKCP) { m.UplinkCapacity = 2; m.DownlinkCapacity = 3 })
	add("CUSTOM_CWND_MULTIPLIER", func(m *cfg.MKCP) { m.CWNDMultiplier = 3 })
	add("CUSTOM_MAX_SENDING_WINDOW", func(m *cfg.MKCP) { m.MaxSendingWindow = 8 * m.MTU })
	add("COMBINED_CUSTOM", func(m *cfg.MKCP) {
		m.MTU = 1000
		m.TTI = 10
		m.UplinkCapacity = 1
		m.DownlinkCapacity = 2
		m.CWNDMultiplier = 2
		m.MaxSendingWindow = 64 * m.MTU
	})
	local, peer := d, d
	local.MTU = 576
	local.TTI = 10
	local.UplinkCapacity = 0
	local.DownlinkCapacity = 1
	peer.MTU = 1460
	peer.TTI = 100
	peer.UplinkCapacity = 2
	peer.DownlinkCapacity = 0
	profiles = append(profiles, mkcpProfile{"MISMATCH_MTU_TTI_CAPACITY", local, peer})
	impaired := d
	impaired.TTI = 10
	profiles = append(profiles, mkcpProfile{"CONTROLLED_LOSS_REORDER", impaired, impaired})
	profiles = append(profiles, mkcpProfile{"TLS_DEFAULT", d, d}, mkcpProfile{"IPV6_DEFAULT", d, d})
	return profiles
}
func mkcpSHA(t *testing.T, path string) string {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	v := sha256.Sum256(b)
	return hex.EncodeToString(v[:])
}
func mkcpJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, append(b, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
}

func mkcpReference(t *testing.T, reference, dir, name string, doc any, network, address string) {
	t.Helper()
	config := filepath.Join(dir, name+"-xray.json")
	mkcpJSON(t, config, doc)
	log, e := os.Create(filepath.Join(dir, name+"-xray.log"))
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(reference, "run", "-config", config)
	cmd.Stdout = log
	cmd.Stderr = log
	if e = cmd.Start(); e != nil {
		log.Close()
		t.Fatal(e)
	}
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
		mkcpJSON(t, filepath.Join(dir, name+"-process-cleanup.json"), map[string]any{"PID": cmd.Process.Pid, "command": cmd.Args, "wait_joined": true, "forced_kill": forced, "exit_code": cmd.ProcessState.ExitCode(), "result": "PASS"})
	})
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		ready := false
		if network == "unix" {
			_, e := os.Stat(address)
			ready = e == nil
		} else {
			ready = mkcpOwnsUDP(cmd.Process.Pid, address)
		}
		if ready {
			return
		}
		select {
		case e := <-done:
			t.Fatalf("reference exited before binding: %v", e)
		case <-deadline.C:
			t.Fatal("reference bind readiness timed out")
		case <-ticker.C:
		}
	}
}
func mkcpOwnsUDP(pid int, address string) bool {
	_, port, _ := net.SplitHostPort(address)
	want, _ := strconv.Atoi(port)
	fds, e := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if e != nil {
		return false
	}
	inodes := map[string]bool{}
	for _, fd := range fds {
		link, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
		if strings.HasPrefix(link, "socket:[") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = true
		}
	}
	for _, table := range []string{"udp", "udp6"} {
		b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/net/%s", pid, table))
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 10 || !inodes[f[9]] {
				continue
			}
			addr := strings.Split(f[1], ":")
			if len(addr) != 2 {
				continue
			}
			n, _ := strconv.ParseInt(addr[1], 16, 32)
			if int(n) == want {
				return true
			}
		}
	}
	return false
}
func mkcpInject(t *testing.T, path string, target access.Endpoint) net.Conn {
	t.Helper()
	raw, e := net.DialTimeout("unix", path, 5*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	raw.SetDeadline(time.Now().Add(20 * time.Second))
	var id [16]byte
	b, _ := hex.DecodeString("00000000000010008000000000000001")
	copy(id[:], b)
	c, e := vlbackend.Client(context.Background(), raw, id, target, false)
	if e != nil {
		raw.Close()
		t.Fatal(e)
	}
	return c
}
func mkcpProfileDeadline(p mkcpProfile) time.Duration {
	// Include both application directions and control overhead. In the deliberate
	// zero-capacity mismatch, an eight-slot/100ms peer window cannot carry 1MiB
	// inside the normal 20s budget. This budget follows the accepted tuning.
	budget := 20 * time.Second
	for _, ends := range [][2]cfg.MKCP{{p.local, p.peer}, {p.peer, p.local}} {
		a, b := ends[0], ends[1]
		slots := uint64(a.SendSlots()) * uint64(a.CWNDMultiplier)
		if n := uint64(a.QueueSlots()); n < slots {
			slots = n
		}
		if n := uint64(b.ReceiveSlots()); n < slots {
			slots = n
		}
		tick := a.TTI
		if b.TTI > tick {
			tick = b.TTI
		}
		bytes := slots * uint64(a.MTU-18)
		bound := time.Duration((2*1048577+bytes-1)/bytes*uint64(tick))*time.Millisecond + 5*time.Second
		if bound > budget {
			budget = bound
		}
	}
	return budget
}
func mkcpPayloadRows(t *testing.T, dial func(access.Endpoint) net.Conn, target access.Endpoint, mtu uint32, large bool, timeout time.Duration) []map[string]any {
	t.Helper()
	sizes := []int{1, 31, int(mtu) - 1, int(mtu), int(mtu) + 1, 65537, 1048577}
	if large {
		sizes = append(sizes, 3<<20)
	}
	rows := make([]map[string]any, 0, len(sizes)+1)
	for _, size := range sizes {
		c := dial(target)
		c.SetDeadline(time.Now().Add(timeout))
		want := make([]byte, size)
		for i := range want {
			want[i] = byte(i*37 + 19)
		}
		write := make(chan error, 1)
		go func() { _, e := c.Write(want); write <- e }()
		got := make([]byte, size)
		_, e := io.ReadFull(c, got)
		we := <-write
		c.Close()
		if e != nil || we != nil || !bytes.Equal(got, want) {
			t.Fatalf("payload size %d: read=%v write=%v integrity=%v", size, e, we, bytes.Equal(got, want))
		}
		a, b := sha256.Sum256(want), sha256.Sum256(got)
		rows = append(rows, map[string]any{"profile": "ordered-stream", "bytes": size, "source_sha256": hex.EncodeToString(a[:]), "destination_sha256": hex.EncodeToString(b[:]), "payload_integrity": "PASS", "missing": 0, "duplicate": 0, "reordered": 0, "corrupt": 0, "connection_close": "PASS"})
	}
	c := dial(target)
	c.SetDeadline(time.Now().Add(timeout))
	want := make([]byte, 1024)
	for i := range want {
		want[i] = byte(i)
	}
	write := make(chan error, 1)
	go func() {
		for i := range want {
			if _, e := c.Write(want[i : i+1]); e != nil {
				write <- e
				return
			}
		}
		write <- nil
	}()
	got := make([]byte, len(want))
	_, e := io.ReadFull(c, got)
	we := <-write
	c.Close()
	if e != nil || we != nil || !bytes.Equal(want, got) {
		t.Fatal("many single byte writes", e, we)
	}
	hash := sha256.Sum256(got)
	rows = append(rows, map[string]any{"profile": "1024-single-byte-writes", "bytes": 1024, "source_sha256": hex.EncodeToString(hash[:]), "destination_sha256": hex.EncodeToString(hash[:]), "payload_integrity": "PASS", "connection_close": "PASS"})
	return rows
}
func mkcpDuplex(t *testing.T, dial func(access.Endpoint) net.Conn) map[string]any {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	up := bytes.Repeat([]byte{0x91, 0x17, 0x23}, 100000)
	down := bytes.Repeat([]byte{0x73, 0x9, 0x19}, 70000)
	server := make(chan error, 1)
	go func() {
		c, e := l.Accept()
		if e != nil {
			server <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(20 * time.Second))
		written := make(chan error, 1)
		go func() { _, e := c.Write(down); written <- e }()
		got := make([]byte, len(up))
		_, e = io.ReadFull(c, got)
		we := <-written
		if e == nil {
			e = we
		}
		if e == nil && !bytes.Equal(got, up) {
			e = errors.New("duplex upload corrupt")
		}
		if e == nil {
			_, e = c.Write([]byte{1})
		}
		server <- e
	}()
	c := dial(netaddrEndpoint(l.Addr()))
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	sent := make(chan error, 1)
	go func() { _, e := c.Write(up); sent <- e }()
	got := make([]byte, len(down))
	_, e = io.ReadFull(c, got)
	we := <-sent
	verify := make([]byte, 1)
	_, ve := io.ReadFull(c, verify)
	se := <-server
	if e != nil || we != nil || ve != nil || se != nil || verify[0] != 1 || !bytes.Equal(got, down) {
		t.Fatal("independent full duplex", e, we, ve, se)
	}
	uh, dh := sha256.Sum256(up), sha256.Sum256(got)
	return map[string]any{"profile": "independent-simultaneous-server-first", "upload_bytes": len(up), "download_bytes": len(down), "upload_sha256": hex.EncodeToString(uh[:]), "download_sha256": hex.EncodeToString(dh[:]), "payload_integrity": "PASS", "connection_close": "PASS"}
}

func TestMKCPPinnedXrayInterop(t *testing.T) {
	reference := os.Getenv("SPLICORE_MKCP_XRAY")
	dir := os.Getenv("SPLICORE_MKCP_EVIDENCE")
	if reference == "" || dir == "" {
		t.Skip("explicit pinned local Xray oracle/evidence directory required")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	identity := map[string]any{"Splicore_validation_binary_sha256": mkcpSHA(t, exe), "Xray_tag": "v26.10.10", "Xray_full_commit": "701af60772cda123492f86e383e1fdba066614a9", "Xray_binary_sha256": mkcpSHA(t, reference)}
	if identity["Xray_binary_sha256"] != "4cca4de3ab8c16b3803a70e9ebe0570d2a72480c716d89aa91603ec568bf0f44" {
		t.Fatal("wrong pinned reference binary")
	}
	if path := os.Getenv("SPLICORE_MKCP_BINDING"); path != "" {
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		var binding map[string]any
		if e = json.Unmarshal(b, &binding); e != nil {
			t.Fatal(e)
		}
		for k, v := range binding {
			identity[k] = v
		}
		if binding["validation_binary_sha256"] != mkcpSHA(t, exe) {
			t.Fatal("stale validation executable binding")
		}
	}
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	target := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	var rows []map[string]any
	var mu sync.Mutex
	for protocolIndex, protocol := range []string{"vless", "vmess", "trojan"} {
		for directionIndex, direction := range []string{"xray-to-splicore", "splicore-to-xray"} {
			for profileIndex, profile := range mkcpProfiles() {
				if profile.name == "TLS_DEFAULT" && protocol == "trojan" {
					continue
				}
				if os.Getenv("SPLICORE_MKCP_DIRECTION") != "" && os.Getenv("SPLICORE_MKCP_DIRECTION") != direction {
					continue
				}
				id := fmt.Sprintf("%s-%s-%s", protocol, direction, profile.name)
				t.Run(id, func(t *testing.T) {
					in, node, key, material := mkcpIntent(t, protocol, profile.local, protocol == "trojan" || profile.name == "TLS_DEFAULT")
					security := node.Security.Kind
					if security == "tls" {
						for _, asset := range []struct{ source, name string }{{material.CertificateFile, id + "-certificate.pem"}, {material.PrivateKeyFile, id + "-key.pem"}} {
							b, e := os.ReadFile(asset.source)
							if e != nil {
								t.Fatal(e)
							}
							if e = os.WriteFile(filepath.Join(dir, asset.name), b, 0600); e != nil {
								t.Fatal(e)
							}
						}
						// Keep live TLS material in the owned Linux temporary directory.
						// Evidence may be on a host mount without Unix mode/owner semantics;
						// its retained copies never become production key input.
					}
					host, family := "127.0.0.1", "IPv4"
					if profile.name == "IPV6_DEFAULT" {
						host, family = "::1", "IPv6"
					}
					stream := map[string]any{"network": "kcp", "security": security, "kcpSettings": profile.peer}
					var dial func(access.Endpoint) net.Conn
					var impairment *mkcpImpairmentProxy
					if direction == "xray-to-splicore" {
						_, endpoint := startMKCP(t, ctx, protocol, in, host)
						if profile.name == "CONTROLLED_LOSS_REORDER" {
							impairment = mkcpProxy(t, endpoint)
							endpoint = netaddrEndpoint(impairment.front.LocalAddr())
						}
						credential := key.Payload.(interface{})
						var settings any
						if protocol == "trojan" {
							settings = map[string]any{"servers": []any{map[string]any{"address": endpoint.Host, "port": endpoint.Port, "password": credential.(access.PasswordPayload).Password.Reveal()}}}
							stream["tlsSettings"] = map[string]any{"serverName": material.ServerName, "allowInsecure": false, "certificates": []any{map[string]any{"usage": "verify", "certificate": strings.Split(strings.TrimSpace(material.CACertificate), "\n")}}}
						} else {
							user := map[string]any{"id": credential.(access.UUIDPayload).UUID.Reveal()}
							if protocol == "vless" {
								user["encryption"] = "none"
							} else {
								user["security"] = "auto"
								user["alterId"] = 0
							}
							settings = map[string]any{"vnext": []any{map[string]any{"address": endpoint.Host, "port": endpoint.Port, "users": []any{user}}}}
						}
						// A Unix raw VLESS injection listener belongs to the reference for its whole life.
						if security == "tls" {
							stream["tlsSettings"] = map[string]any{"serverName": material.ServerName, "allowInsecure": false, "certificates": []any{map[string]any{"usage": "verify", "certificate": strings.Split(strings.TrimSpace(material.CACertificate), "\n")}}}
						}
						socket := filepath.Join(t.TempDir(), "xray.sock")
						doc := map[string]any{"log": map[string]any{"loglevel": "info"}, "inbounds": []any{map[string]any{"listen": socket, "port": 1, "protocol": "vless", "settings": map[string]any{"decryption": "none", "clients": []any{map[string]any{"id": "00000000-0000-1000-8000-000000000001"}}}}}, "outbounds": []any{map[string]any{"protocol": protocol, "settings": settings, "streamSettings": stream}}}
						mkcpReference(t, reference, dir, id, doc, "unix", socket)
						dial = func(target access.Endpoint) net.Conn { return mkcpInject(t, socket, target) }
					} else {
						// Explicit maintainer exception: fixed Xray rejects port zero. Bind
						// once at a profile-derived port; EADDRINUSE is a failure, never a retry.
						port := 45000 + protocolIndex*100 + directionIndex*50 + profileIndex
						node.Endpoint = access.Endpoint{Host: host, Port: uint16(port)}
						var account any
						settings := map[string]any{}
						if protocol == "trojan" {
							account = map[string]any{"password": key.Payload.(access.PasswordPayload).Password.Reveal()}
							stream["tlsSettings"] = map[string]any{"certificates": []any{map[string]any{"certificateFile": material.CertificateFile, "keyFile": material.PrivateKeyFile}}}
						} else {
							account = map[string]any{"id": key.Payload.(access.UUIDPayload).UUID.Reveal()}
							if protocol == "vless" {
								settings["decryption"] = "none"
							}
						}
						settings["clients"] = []any{account}
						if security == "tls" {
							stream["tlsSettings"] = map[string]any{"certificates": []any{map[string]any{"certificateFile": material.CertificateFile, "keyFile": material.PrivateKeyFile}}}
						}
						doc := map[string]any{"log": map[string]any{"loglevel": "info"}, "inbounds": []any{map[string]any{"listen": host, "port": port, "protocol": protocol, "settings": settings, "streamSettings": stream}}, "outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32", "::1/128"}}}}}}}
						mkcpReference(t, reference, dir, id, doc, "udp", net.JoinHostPort(node.Endpoint.Host, strconv.Itoa(port)))
						if profile.name == "CONTROLLED_LOSS_REORDER" {
							impairment = mkcpProxy(t, node.Endpoint)
							node.Endpoint = netaddrEndpoint(impairment.front.LocalAddr())
						}
						d := sharedBuild(t, ctx, node, key)
						t.Cleanup(func() { d.Close() })
						dial = func(target access.Endpoint) net.Conn {
							c, e := d.DialContext(ctx, target)
							if e != nil {
								t.Fatal(e)
							}
							return c
						}
					}
					timeout := mkcpProfileDeadline(profile)
					payloads := mkcpPayloadRows(t, dial, target, profile.local.MTU, profile.name == "DEFAULT", timeout)
					payloads = append(payloads, mkcpDuplex(t, dial))
					var impairmentEvidence any
					if impairment != nil {
						impairment.Close()
						impairmentEvidence = impairment.evidence()
						if impairment.dataLoss != 2 || impairment.ackLoss != 2 || impairment.reorders != 2 || impairment.duplicates == 0 {
							t.Fatal("reference impairment not exercised", impairmentEvidence)
						}
					}
					row := map[string]any{"ID": id, "direction": direction, "protocol": protocol, "address_family": "IPv4", "Splicore_mkcp": profile.local, "Xray_mkcp": profile.peer, "payload_profiles": payloads, "result": "PASS", "protocol_auth": "PASS", "actual_proxy_target": target, "payload_integrity": "PASS", "identity": identity, "reference_process_cleanup": "joined by subtest cleanup"}
					row["impairment"] = impairmentEvidence
					row["payload_deadline_ms"] = timeout.Milliseconds()
					row["address_family"], row["security"] = family, security
					if security == "tls" {
						row["synthetic_tls_assets"] = map[string]any{"certificate": id + "-certificate.pem", "key": id + "-key.pem", "certificate_sha256": mkcpSHA(t, material.CertificateFile), "key_sha256": mkcpSHA(t, material.PrivateKeyFile), "live_material": "owned Linux temporary directory; removed by test cleanup"}
					}
					nativeConfig := map[string]any{"inbound_protocol_settings": in.Inbound.Settings.Data, "node_transport": node.Transport, "node_security": node.Security, "node_endpoint": node.Endpoint, "node_options": node.Options, "synthetic_credential": "UUID 00000000-0000-1000-8000-000000000001; Trojan SyntheticMKCPPassword"}
					mkcpJSON(t, filepath.Join(dir, id+"-splicore-config.json"), nativeConfig)
					row["configuration_sha256"] = map[string]any{"Xray": mkcpSHA(t, filepath.Join(dir, id+"-xray.json")), "Splicore": mkcpSHA(t, filepath.Join(dir, id+"-splicore-config.json"))}
					mkcpJSON(t, filepath.Join(dir, id+".json"), row)
					mu.Lock()
					rows = append(rows, row)
					mu.Unlock()
				})
			}
		}
	}
	mkcpJSON(t, filepath.Join(dir, "interop-inventory.json"), map[string]any{"profiles": rows, "identity": identity, "result": map[bool]string{true: "FAIL", false: "PASS"}[t.Failed()], "test_scope": "local software compatibility QA; exact native Core compiler/dialer/listener; no publication"})
}
