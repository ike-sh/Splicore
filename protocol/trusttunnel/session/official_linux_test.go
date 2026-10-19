//go:build linux && with_quic

package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
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
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks5"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
)

type oracleProcess struct {
	cmd  *exec.Cmd
	done chan struct{}
	log  *os.File
	dir  string
	once sync.Once
	err  error
}

func oracleRoot(t *testing.T) string {
	t.Helper()
	root := os.Getenv("SPLICORE_TRUSTTUNNEL_REFERENCE_ROOT")
	if root == "" {
		t.Skip("official reference artifacts not configured")
	}
	return root
}
func oracleStart(t *testing.T, dir, binary string, args ...string) *oracleProcess {
	t.Helper()
	data, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(data)
	expected := ""
	switch filepath.Base(binary) {
	case "trusttunnel_endpoint":
		expected = "9bb15f4e30e2ff196cf0aa387462c42387d9405ddfeb5caad133838560fa33cd"
	case "trusttunnel_client":
		expected = "e01411457f65c498063211fa670d55ea710d3a2d35534acd73438bd514df454a"
	default:
		t.Fatal("unrecognized oracle")
	}
	if hex.EncodeToString(sum[:]) != expected {
		t.Fatal("reference binary pin mismatch")
	}
	identity := map[string]any{"binary": binary, "sha256": expected, "architecture": "linux-x86_64"}
	record, _ := json.MarshalIndent(identity, "", "  ")
	oracleWrite(t, dir, "reference-identity.json", string(record))
	log, e := os.Create(filepath.Join(dir, "reference.log"))
	if e != nil {
		t.Fatal(e)
	}
	command := append([]string{binary}, args...)
	b, _ := json.MarshalIndent(command, "", "  ")
	if e = os.WriteFile(filepath.Join(dir, "command.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(binary, args...)
	cmd.Dir = dir
	cmd.Stdout = log
	cmd.Stderr = log
	p := &oracleProcess{cmd: cmd, done: make(chan struct{}), log: log, dir: dir}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	go func() { p.err = cmd.Wait(); close(p.done) }()
	t.Cleanup(func() { p.close(t) })
	return p
}
func (p *oracleProcess) close(t *testing.T) {
	p.once.Do(func() {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-p.done:
		case <-timer.C:
			_ = p.cmd.Process.Kill()
			<-p.done
			t.Error("reference required forced shutdown")
		}
		_ = p.log.Close()
		b, _ := json.Marshal(map[string]any{"pid": p.cmd.Process.Pid, "exit": fmt.Sprint(p.err), "joined": true})
		_ = os.WriteFile(filepath.Join(p.dir, "exit.json"), b, 0600)
	})
}

// Discover only sockets held by the running reference. No probe listener is
// created or closed, and no discovered port is ever rebound.
func (p *oracleProcess) address(t *testing.T, network string) string {
	socks := network == "socks"
	if socks {
		network = "tcp"
	}
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		inodes := map[string]bool{}
		fds, _ := filepath.Glob(fmt.Sprintf("/proc/%d/fd/*", p.cmd.Process.Pid))
		for _, fd := range fds {
			link, _ := os.Readlink(fd)
			if strings.HasPrefix(link, "socket:[") {
				inodes[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = true
			}
		}
		expected := ""
		if socks {
			log, _ := os.ReadFile(filepath.Join(p.dir, "reference.log"))
			for _, line := range strings.Split(string(log), "\n") {
				if strings.Contains(line, "SOCKS5_LISTENER") && strings.Contains(line, "Listening on ") {
					_, expected, _ = strings.Cut(line, "Listening on ")
					expected = strings.TrimSpace(expected)
				}
			}
		}
		table, _ := os.ReadFile("/proc/net/" + network)
		table6, _ := os.ReadFile("/proc/net/" + network + "6")
		table = append(append(table, '\n'), table6...)
		for _, line := range strings.Split(string(table), "\n") {
			f := strings.Fields(line)
			if len(f) < 10 || !inodes[f[9]] {
				continue
			}
			if network == "tcp" && f[3] != "0A" {
				continue
			}
			parts := strings.Split(f[1], ":")
			if len(parts) != 2 {
				continue
			}
			port, e := strconv.ParseUint(parts[1], 16, 16)
			if e != nil || port == 0 {
				continue
			}
			address := "127.0.0.1:" + strconv.Itoa(int(port))
			if len(parts[0]) == 32 {
				address = "[::1]:" + strconv.Itoa(int(port))
			}
			if socks && address != expected {
				continue
			}
			b, _ := json.Marshal(map[string]any{"network": network, "address": address, "inode": f[9], "listener_owned": true, "requested_port": 0})
			_ = os.WriteFile(filepath.Join(p.dir, network+"-listener.json"), b, 0600)
			return address
		}
		select {
		case <-p.done:
			b, _ := os.ReadFile(filepath.Join(p.dir, "reference.log"))
			t.Fatalf("reference stopped before listener: %s", b)
		case <-deadline.C:
			b, _ := os.ReadFile(filepath.Join(p.dir, "reference.log"))
			t.Fatalf("reference listener unavailable: %s", b)
		case <-tick.C:
		}
	}
}
func (p *oracleProcess) waitConnected(t *testing.T) {
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		b, _ := os.ReadFile(filepath.Join(p.dir, "reference.log"))
		if strings.Contains(string(b), "Successfully connected to endpoint") {
			return
		}
		select {
		case <-timer.C:
			t.Fatal("official client never READY")
		case <-p.done:
			t.Fatal("official client exited before READY")
		case <-tick.C:
		}
	}
}
func referenceBoundary(t *testing.T, root, mode, network string, size int, err error) {
	t.Helper()
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("unexpected boundary failure: %v", err)
	}
	b, e := os.ReadFile(filepath.Join(root, "official-self-01/result.json"))
	if e != nil {
		t.Fatal("reference self evidence required", e)
	}
	var rows []struct {
		Mode, Network, Status string
		Size                  int
	}
	if json.Unmarshal(b, &rows) != nil {
		t.Fatal("invalid reference self evidence")
	}
	if mode == "auto" {
		mode = "http3"
	}
	for _, row := range rows {
		if row.Mode == mode && row.Network == network && row.Size == size && row.Status == "FAIL" {
			return
		}
	}
	t.Fatal("no matching official self limitation")
}
func oracleDir(t *testing.T, root, label string) string {
	t.Helper()
	dir, e := os.MkdirTemp(root, "interop-"+label+"-")
	if e != nil {
		t.Fatal(e)
	}
	return dir
}
func oracleWrite(t *testing.T, dir, name, value string) {
	t.Helper()
	if e := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); e != nil {
		t.Fatal(e)
	}
}

func startOfficialEndpoint(t *testing.T, root string, icmp bool, options ...string) (string, string, string, *tls.Config) {
	dir := oracleDir(t, root, "endpoint")
	settings := testkit.TLS(t)
	cert, _ := os.ReadFile(settings.CertificateFile)
	key, _ := os.ReadFile(settings.PrivateKeyFile)
	oracleWrite(t, dir, "cert.pem", string(cert))
	oracleWrite(t, dir, "key.pem", string(key))
	oracleWrite(t, dir, "ca.pem", settings.CACertificate)
	oracleWrite(t, dir, "credentials.toml", "[[client]]\nusername = \"alpha\"\npassword = \"alpha-pass\"\n[[client]]\nusername = \"beta\"\npassword = \"beta-pass\"\n")
	mode, listen := "dual", "127.0.0.1:0"
	if len(options) > 0 {
		mode = options[0]
	}
	if len(options) > 1 {
		listen = options[1]
	}
	config := fmt.Sprintf("listen_address = %q\nallow_private_network_connections = true\ncredentials_file = \"credentials.toml\"\n", listen)
	if mode != "http3" {
		config += "[listen_protocols.http2]\n"
	}
	if mode != "http2" {
		config += "[listen_protocols.quic]\n"
	}
	if icmp {
		config += "[icmp]\ninterface_name = \"lo\"\nrequest_timeout_secs = 3\n"
	}
	oracleWrite(t, dir, "vpn.toml", config)
	oracleWrite(t, dir, "hosts.toml", fmt.Sprintf("[[main_hosts]]\nhostname = %q\ncert_chain_path = \"cert.pem\"\nprivate_key_path = \"key.pem\"\n", settings.ServerName))
	p := oracleStart(t, dir, filepath.Join(root, "reference/official-endpoint/trusttunnel-v1.1.0-linux-x86_64/trusttunnel_endpoint"), "vpn.toml", "hosts.toml", "--jobs", "2")
	h2, h3 := "", ""
	if mode != "http3" {
		h2 = p.address(t, "tcp")
	}
	if mode != "http2" {
		h3 = p.address(t, "udp")
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(settings.CACertificate))
	tc := &tls.Config{ServerName: settings.ServerName, RootCAs: pool}
	return dir, h2, h3, tc
}
func TestOfficialEndpointBidirectionalPayload(t *testing.T) {
	root := oracleRoot(t)
	dir, h2, h3, tc := startOfficialEndpoint(t, root, false)
	target := tcpEcho(t, "tcp4", "192.0.2.29:0")
	target6 := tcpEcho(t, "tcp6", "[2001:db8::29]:0")
	udp := udpEcho(t, "udp4", "192.0.2.29:0")
	udp6 := udpEcho(t, "udp6", "[2001:db8::29]:0")
	for _, mode := range []string{"http2", "http3", "auto"} {
		t.Run(mode, func(t *testing.T) {
			address := h2
			if mode == "http3" {
				address = h3
			}
			c := newClient(t, mode, address, tc, func(cfg *ClientConfig) {
				if mode == "auto" {
					cfg.Addresses = []string{h3, h2}
					cfg.FallbackDelay = 20 * time.Millisecond
				}
			})
			checks := 0
			boundaries := []map[string]any{}
			for _, target := range []string{target, target6} {
				for _, size := range []int{1, 16 << 10, 64 << 10, 1 << 20, 4 << 20} {
					if e := transfer(c, target, size); e != nil {
						t.Fatalf("TCP target=%s size=%d error=%v", target, size, e)
					}
					t.Logf("TCP target=%s size=%d PASS", target, size)
					checks++
				}
			}
			for _, dst := range []netip.AddrPort{udp, udp6} {
				for range 4 {
					packet, e := c.OpenPacket(context.Background(), dst)
					if e != nil {
						t.Fatal(e)
					}
					_ = packet.SetDeadline(time.Now().Add(5 * time.Second))
					for _, size := range []int{1, 53, 1200, 1350, 1472, 4048, 0} {
						_ = packet.SetDeadline(time.Now().Add(5 * time.Second))
						if size == 0 {
							_ = packet.SetReadDeadline(time.Now().Add(3 * time.Second))
						}
						payload := bytes.Repeat([]byte{byte(size % 251)}, size)
						if _, e := packet.WriteTo(payload, net.UDPAddrFromAddrPort(dst)); e != nil {
							t.Fatal(e)
						}
						b := make([]byte, 65535)
						n, _, e := packet.ReadFrom(b)
						if size == 0 && e != nil {
							referenceBoundary(t, root, mode, "udp", 0, e)
							boundaries = append(boundaries, map[string]any{"network": "UDP", "size": 0, "observed": "FAIL", "classification": "UPSTREAM_REFERENCE_LIMITATION", "evidence": "official-self-01/result.json"})
							t.Log("UDP empty observed=FAIL reference_self=FAIL (not counted PASS)")
							break
						}
						if e != nil || !bytes.Equal(payload, b[:n]) {
							t.Fatal(size, e)
						}
						checks++
					}
					_ = packet.Close()
				}
			}
			if e := c.Check(context.Background()); e != nil {
				t.Fatal(e)
			}
			// Multiplex on the established authenticated session, while health and
			// another user's independent session are active.
			var wg sync.WaitGroup
			errors := make(chan error, 33)
			for range 32 {
				wg.Add(1)
				go func() { defer wg.Done(); errors <- transfer(c, target, 16384) }()
			}
			wg.Add(1)
			go func() { defer wg.Done(); errors <- c.Check(context.Background()) }()
			wg.Wait()
			close(errors)
			for e := range errors {
				if e != nil {
					t.Fatal(e)
				}
			}
			checks += 32
			beta := newClient(t, mode, address, tc, func(cfg *ClientConfig) {
				cfg.Username = "beta"
				cfg.Password = "beta-pass"
				if mode == "auto" {
					cfg.Addresses = []string{h3, h2}
					cfg.FallbackDelay = 20 * time.Millisecond
				}
			})
			if e := transfer(beta, target, 16384); e != nil {
				t.Fatal(e)
			}
			checks++
			report := map[string]any{"direction": "splicore-client-to-official-endpoint", "mode": mode, "payload_checks": checks, "reference_boundaries": boundaries, "TCP_sizes": []int{16384, 65536, 1048576, 4194304, 1}, "UDP_sizes": []int{1, 53, 1200, 1350, 1472, 4048, 0}, "IPv4": true, "IPv6": true, "health": "PASS", "integrity": "byte-for-byte", "exit": 0}
			b, _ := json.MarshalIndent(report, "", "  ")
			oracleWrite(t, dir, mode+".json", string(b))
			t.Logf("official endpoint mode=%s payload_checks=%d integrity=PASS reference_boundary_FAIL=%d", mode, checks, len(boundaries))
		})
	}
	for _, mode := range []string{"http2", "http3"} {
		address := h2
		if mode == "http3" {
			address = h3
		}
		c := newClient(t, mode, address, tc, func(cfg *ClientConfig) { cfg.Password = "incorrect" })
		if e := c.Check(context.Background()); !IsCode(e, Auth) {
			t.Fatal("wrong password", mode, e)
		}
	}
}

func TestOfficialClientToNativeServer(t *testing.T) {
	root := oracleRoot(t)
	for _, mode := range []string{"http2", "http3"} {
		for _, user := range []string{"alpha", "beta"} {
			t.Run(mode+"/"+user, func(t *testing.T) {
				dir := oracleDir(t, root, "client-"+mode)
				settings := testkit.TLS(t)
				cert, _ := os.ReadFile(settings.CertificateFile)
				key, _ := os.ReadFile(settings.PrivateKeyFile)
				pair, e := tls.X509KeyPair(cert, key)
				if e != nil {
					t.Fatal(e)
				}
				address, _, _ := startServer(t, mode, func(cfg *ServerConfig) {
					cfg.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
				})
				config := fmt.Sprintf("loglevel = \"info\"\nvpn_mode = \"general\"\nkillswitch_enabled = true\npost_quantum_group_enabled = false\nexclusions = []\n[endpoint]\nhostname = %q\naddresses = [%q]\nhas_ipv6 = true\nusername = %q\npassword = %q\nskip_verification = false\ncertificate = '''%s'''\nupstream_protocol = %q\nanti_dpi = false\n[listener.socks]\naddress = \"127.0.0.1:0\"\n", settings.ServerName, address, user, user+"-pass", settings.CACertificate, mode)
				oracleWrite(t, dir, "client.toml", config)
				p := oracleStart(t, dir, filepath.Join(root, "reference/official-client/trusttunnel_client-v1.1.11-linux-x86_64/trusttunnel_client"), "-c", "client.toml", "-l", "debug")
				proxy := p.address(t, "socks")
				p.waitConnected(t)
				checks := 0
				boundaries := []map[string]any{}
				for _, target := range []string{tcpEcho(t, "tcp4", "192.0.2.29:0"), tcpEcho(t, "tcp6", "[2001:db8::29]:0")} {
					host, port, _ := net.SplitHostPort(target)
					n, _ := strconv.Atoi(port)
					dst := access.Endpoint{Host: host, Port: uint16(n)}
					for _, size := range []int{16384, 65536, 1048576, 4194304, 1} {
						conn, e := net.DialTimeout("tcp", proxy, 10*time.Second)
						if e != nil {
							t.Fatal(e)
						}
						_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
						if _, e = socks5.Handshake(conn, socks5.Connect, dst); e != nil {
							_ = conn.Close()
							t.Fatal(e)
						}
						if size == 1 {
							_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
						}
						payload := bytes.Repeat([]byte{0x5a}, size)
						written := make(chan error, 1)
						go func() {
							_, e := conn.Write(payload)
							written <- e
						}()
						b := make([]byte, len(payload))
						_, e = io.ReadFull(conn, b)
						we := <-written
						_ = conn.Close()
						if size == 1 && e != nil {
							referenceBoundary(t, root, mode, "tcp", 1, e)
							boundaries = append(boundaries, map[string]any{"network": "TCP", "size": 1, "payload_hex": "5a", "observed": "FAIL", "classification": "UPSTREAM_REFERENCE_LIMITATION", "evidence": "official-self-01/result.json"})
							t.Log("TCP ASCII Z observed=FAIL reference_self=FAIL (not counted PASS)")
							continue
						}
						if e != nil || we != nil || !bytes.Equal(payload, b) {
							t.Fatal(size, e, we)
						}
						checks++
					}
				}
				for _, dst := range []netip.AddrPort{udpEcho(t, "udp4", "192.0.2.29:0"), udpEcho(t, "udp6", "[2001:db8::29]:0")} {
					control, e := net.DialTimeout("tcp", proxy, 10*time.Second)
					if e != nil {
						t.Fatal(e)
					}
					_ = control.SetDeadline(time.Now().Add(15 * time.Second))
					bind, e := socks5.Handshake(control, socks5.UDPAssociate, access.Endpoint{Host: "0.0.0.0", Port: 0})
					if e != nil {
						control.Close()
						t.Fatal("official SOCKS UDP", e)
					}
					socket, e := net.Dial("udp", net.JoinHostPort(bind.Host, strconv.Itoa(int(bind.Port))))
					if e != nil {
						control.Close()
						t.Fatal(e)
					}
					packet := testfixture.SOCKSPacket(socket, control)
					_ = packet.SetDeadline(time.Now().Add(5 * time.Second))
					for _, size := range []int{1, 53, 1200, 1350, 1472, 4048, 0} {
						_ = packet.SetReadDeadline(time.Now().Add(5 * time.Second))
						if size == 0 {
							_ = packet.SetReadDeadline(time.Now().Add(3 * time.Second))
						}
						payload := bytes.Repeat([]byte{0x39}, size)
						if _, e = packet.WriteTo(payload, net.UDPAddrFromAddrPort(dst)); e != nil {
							t.Fatal(e)
						}
						b := make([]byte, 65535)
						n, _, e := packet.ReadFrom(b)
						if size == 0 && e != nil {
							referenceBoundary(t, root, mode, "udp", 0, e)
							boundaries = append(boundaries, map[string]any{"network": "UDP", "size": 0, "observed": "FAIL", "classification": "UPSTREAM_REFERENCE_LIMITATION", "evidence": "official-self-01/result.json"})
							t.Log("UDP empty observed=FAIL reference_self=FAIL (not counted PASS)")
							continue
						}
						if e != nil || sha256.Sum256(payload) != sha256.Sum256(b[:n]) {
							t.Fatal(size, e)
						}
						checks++
					}
					_ = packet.Close()
				}
				summary := map[string]any{"direction": "official-client-to-splicore-server", "mode": mode, "auth_identity": user, "tls_identity": settings.ServerName, "tls_trust": "explicit generated CA", "IPv4": true, "IPv6": true, "server_address": address, "payload_checks": checks, "reference_boundaries": boundaries, "integrity": "SHA256/byte-for-byte", "exit": 0, "TCP_SHA256_4MiB": hex.EncodeToString(func() []byte { v := sha256.Sum256(bytes.Repeat([]byte{0x5a}, 4194304)); return v[:] }())}
				b, _ := json.MarshalIndent(summary, "", "  ")
				oracleWrite(t, dir, "result.json", string(b))
				t.Logf("official client mode=%s payload_checks=%d integrity=PASS reference_boundary_FAIL=%d", mode, checks, len(boundaries))
			})
		}
	}
}
