//go:build linux && with_quic

package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks5"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"

	"github.com/ike-sh/Splicore/protocol/trusttunnel/deeplink"
	"github.com/ike-sh/Splicore/protocol/trusttunnel/wire"
)

func oracleCommand(t *testing.T, dir, label, binary string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = dir
	b, e := cmd.CombinedOutput()
	command, _ := json.Marshal(append([]string{binary}, args...))
	oracleWrite(t, dir, label+"-command.json", string(command))
	oracleWrite(t, dir, label+"-output.log", string(b))
	if e != nil {
		t.Fatalf("oracle %s exit: %v", label, e)
	}
	return b
}
func TestOfficialDeepLinkCompatibility(t *testing.T) {
	root := oracleRoot(t)
	dir, h2, _, _ := startOfficialEndpoint(t, root, false)
	endpoint := filepath.Join(root, "reference/official-endpoint/trusttunnel-v1.1.0-linux-x86_64/trusttunnel_endpoint")
	output := oracleCommand(t, dir, "endpoint-export", endpoint, "vpn.toml", "hosts.toml", "-c", "alpha", "-a", h2, "--format", "deeplink")
	var raw string
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "tt://") {
			raw = strings.TrimSpace(line)
		}
	}
	l, e := deeplink.Parse(raw)
	if e != nil || l.Username != "alpha" || l.Password != "alpha-pass" || len(l.Addresses) != 1 || l.Addresses[0] != h2 {
		t.Fatal("official endpoint link incompatible", e)
	}
	// The pinned official wizard independently verifies our static serialization.
	l.Name = "Splicore synthetic compatibility"
	l.Protocol = "http3"
	encoded, e := deeplink.Encode(l)
	if e != nil {
		t.Fatal(e)
	}
	wizard := filepath.Join(root, "reference/official-client/trusttunnel_client-v1.1.11-linux-x86_64/setup_wizard")
	b, e := os.ReadFile(wizard)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != "ac781f036cda54d6efd1b133b66b9487e0da3f7d6ae36cd3de233cfe7b9d82c4" {
		t.Fatal("wizard pin mismatch")
	}
	oracleWrite(t, dir, "wizard-sha256.txt", hex.EncodeToString(sum[:]))
	oracleCommand(t, dir, "wizard-import", wizard, "--mode", "non-interactive", "--deeplink", encoded, "--settings", "imported.toml")
	imported, e := os.ReadFile(filepath.Join(dir, "imported.toml"))
	if e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{`username = "alpha"`, `password = "alpha-pass"`, `upstream_protocol = "http3"`, l.Hostname, h2} {
		if !strings.Contains(string(imported), field) {
			t.Fatal("official importer dropped connection field")
		}
	}
	report, _ := json.MarshalIndent(map[string]any{"endpoint_to_splicore": "PASS", "splicore_to_official_wizard": "PASS", "official_client_reexport": "UNAVAILABLE in pinned v1.1.11 CLI", "observed_endpoint_version": l.Version, "export_version": 1, "scope": "static H2/H3 connection fields", "optional_extensions": "NOT QUALIFIED", "exit": 0}, "", "  ")
	oracleWrite(t, dir, "deep-link-result.json", string(report))
}

func TestOfficialEndpointICMPObservation(t *testing.T) {
	root := oracleRoot(t)
	dir, h2, h3, tc := startOfficialEndpoint(t, root, true)
	rows := []map[string]any{}
	for _, mode := range []string{"http2", "http3"} {
		address := h2
		if mode == "http3" {
			address = h3
		}
		c := newClient(t, mode, address, tc, nil)
		for _, ip := range []string{"192.0.2.29", "2001:db8::29"} {
			for _, ttl := range []uint8{32, 64} {
				r := wire.EchoRequest{ID: 37, Sequence: uint16(ttl), Destination: netip.MustParseAddr(ip), TTL: ttl, DataSize: 32}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				reply, e := c.Echo(ctx, r)
				cancel()
				observed := "PASS"
				if e != nil || reply.ID != r.ID || reply.Sequence != r.Sequence || reply.Source != r.Destination {
					observed = "FAIL"
				}
				rows = append(rows, map[string]any{"mode": mode, "destination": ip, "ttl": ttl, "observed": observed, "error": errorText(e), "reply_type": reply.Type, "reply_code": reply.Code})
				t.Logf("ICMP observation mode=%s ip=%s ttl=%d result=%s error=%v", mode, ip, ttl, observed, e)
			}
		}
	}
	b, _ := json.MarshalIndent(map[string]any{"direction": "Splicore-client-to-official-endpoint", "payload_observations": rows, "capability_claim": "IMPLEMENTED / NOT YET QUALIFIED", "reason": "official-client TUN direction and raw error types are not qualified"}, "", "  ")
	oracleWrite(t, dir, "icmp-observation.json", string(b))
}
func errorText(e error) string {
	if e != nil {
		return e.Error()
	}
	return ""
}

func TestOfficialClientWrongCredentials(t *testing.T) {
	root := oracleRoot(t)
	for _, mode := range []string{"http2", "http3"} {
		t.Run(mode, func(t *testing.T) {
			dir := oracleDir(t, root, "wrong-client-"+mode)
			settings := testkit.TLS(t)
			cert, _ := os.ReadFile(settings.CertificateFile)
			key, _ := os.ReadFile(settings.PrivateKeyFile)
			pair, e := tls.X509KeyPair(cert, key)
			if e != nil {
				t.Fatal(e)
			}
			rejected := make(chan struct{})
			var once sync.Once
			var dials atomic.Int32
			a, _, _ := startServer(t, mode, func(cfg *ServerConfig) {
				cfg.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
				cfg.Authenticate = func(u, p string) (string, bool) { once.Do(func() { close(rejected) }); return "", false }
				cfg.DialTCP = func(context.Context, string, string) (net.Conn, error) {
					dials.Add(1)
					return nil, fmt.Errorf("unexpected dial")
				}
			})
			config := fmt.Sprintf("loglevel = \"debug\"\nvpn_mode = \"general\"\nkillswitch_enabled = true\npost_quantum_group_enabled = false\nexclusions = []\n[endpoint]\nhostname = %q\naddresses = [%q]\nhas_ipv6 = true\nusername = \"alpha\"\npassword = \"wrong-password\"\nskip_verification = false\ncertificate = '''%s'''\nupstream_protocol = %q\nanti_dpi = false\n[listener.socks]\naddress = \"127.0.0.1:0\"\n", settings.ServerName, a, settings.CACertificate, mode)
			oracleWrite(t, dir, "client.toml", config)
			p := oracleStart(t, dir, filepath.Join(root, "reference/official-client/trusttunnel_client-v1.1.11-linux-x86_64/trusttunnel_client"), "-c", "client.toml", "-l", "debug")
			proxy := p.address(t, "socks")
			select {
			case <-rejected:
			case <-time.After(10 * time.Second):
				t.Fatal("official client auth never reached server")
			}
			target := tcpEcho(t, "tcp4", "192.0.2.29:0")
			host, port, _ := net.SplitHostPort(target)
			number, _ := strconv.Atoi(port)
			// A rejected official client may retire its SOCKS listener. Both a
			// refused listener and a failed payload prove no forwarding, but only
			// after the server independently observed and rejected authentication.
			conn, e := net.DialTimeout("tcp", proxy, 3*time.Second)
			failureStage := "SOCKS listener connect"
			if e == nil {
				failureStage = "SOCKS handshake/payload"
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				_, e = socks5.Handshake(conn, socks5.Connect, access.Endpoint{Host: host, Port: uint16(number)})
				if e == nil {
					payload := bytes.Repeat([]byte{0x5a}, 16384)
					_, e = conn.Write(payload)
					if e == nil {
						_, e = io.ReadFull(conn, make([]byte, len(payload)))
					}
				}
				conn.Close()
			}
			p.close(t)
			if e == nil || dials.Load() != 0 {
				t.Fatal("wrong credential admitted")
			}
			report, _ := json.Marshal(map[string]any{"direction": "official-client-to-splicore-server", "mode": mode, "auth_identity": "synthetic-invalid", "observed_auth_rejection": true, "forwarding_failure_stage": failureStage, "forwarding_error": errorText(e), "unexpected_target_dials": dials.Load(), "result": "PASS", "exit": 0})
			oracleWrite(t, dir, "negative-result.json", string(report))
		})
	}
}

func TestOfficialAutoSelectionRestrictions(t *testing.T) {
	root := oracleRoot(t)
	for _, profile := range []string{"h2-only", "h3-only", "udp-blocked", "tcp-blocked", "h3-delayed", "h2-delayed", "hostname", "IPv6-endpoint", "certificate-mismatch", "wrong-password"} {
		t.Run(profile, func(t *testing.T) {
			serverMode, listen := "dual", "127.0.0.1:0"
			if profile == "h2-only" {
				serverMode = "http2"
			}
			if profile == "h3-only" {
				serverMode = "http3"
			}
			if profile == "IPv6-endpoint" {
				listen = "[::1]:0"
			}
			dir, h2, h3, tc := startOfficialEndpoint(t, root, false, serverMode, listen)
			addresses := []string{}
			if h3 != "" {
				addresses = append(addresses, h3)
			}
			if h2 != "" {
				addresses = append(addresses, h2)
			}
			if profile == "hostname" {
				for i, a := range addresses {
					_, port, _ := net.SplitHostPort(a)
					addresses[i] = net.JoinHostPort("localhost", port)
				}
			}
			c := newClient(t, "auto", addresses[0], tc, func(cfg *ClientConfig) {
				cfg.Addresses = addresses
				cfg.FallbackDelay = 5 * time.Millisecond
				cfg.ConnectTimeout = time.Second
				if profile == "udp-blocked" {
					cfg.PacketSocket = func(context.Context, string) (net.PacketConn, net.Addr, error) { return nil, nil, io.ErrClosedPipe }
				}
				if profile == "tcp-blocked" {
					cfg.DialTCP = func(context.Context, string, string) (net.Conn, error) { return nil, io.ErrClosedPipe }
				}
				if profile == "h3-delayed" {
					cfg.PacketSocket = func(ctx context.Context, _ string) (net.PacketConn, net.Addr, error) {
						<-ctx.Done()
						return nil, nil, ctx.Err()
					}
				}
				if profile == "h2-delayed" {
					cfg.DialTCP = func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
				}
				if profile == "certificate-mismatch" {
					cfg.TLS = tc.Clone()
					cfg.TLS.ServerName = "wrong.test"
					cfg.FallbackDelay = time.Second
				}
				if profile == "wrong-password" {
					cfg.Password = "wrong-password"
					cfg.FallbackDelay = time.Second
				}
			})
			e := c.Check(context.Background())
			checks := 0
			selected := ""
			if profile == "certificate-mismatch" {
				if !IsCode(e, Certificate) {
					t.Fatal(e)
				}
			} else if profile == "wrong-password" {
				if !IsCode(e, Auth) {
					t.Fatal(e)
				}
			} else {
				if e != nil {
					t.Fatal(e)
				}
				c.mu.Lock()
				selected = c.session.mode
				c.mu.Unlock()
				if (profile == "h2-only" || profile == "udp-blocked" || profile == "h3-delayed") && selected != "http2" {
					t.Fatal(selected)
				}
				if (profile == "h3-only" || profile == "tcp-blocked" || profile == "h2-delayed") && selected != "http3" {
					t.Fatal(selected)
				}
				target := tcpEcho(t, "tcp4", "192.0.2.29:0")
				if e := transfer(c, target, 16384); e != nil {
					t.Fatal(e)
				}
				checks++
				for range 8 {
					if e := c.Check(context.Background()); e != nil {
						t.Fatal(e)
					}
					if e := transfer(c, target, 16384); e != nil {
						t.Fatal("post-health EOF continuity", e)
					}
					checks++
				}
				dst := udpEcho(t, "udp4", "192.0.2.29:0")
				packet, e := c.OpenPacket(context.Background(), dst)
				if e != nil {
					t.Fatal(e)
				}
				defer packet.Close()
				packet.SetDeadline(time.Now().Add(3 * time.Second))
				payload := bytes.Repeat([]byte{0x73}, 1472)
				if _, e = packet.WriteTo(payload, net.UDPAddrFromAddrPort(dst)); e != nil {
					t.Fatal(e)
				}
				b := make([]byte, 65535)
				n, _, e := packet.ReadFrom(b)
				if e != nil || !bytes.Equal(payload, b[:n]) {
					t.Fatal(e)
				}
				checks++
			}
			result, _ := json.Marshal(map[string]any{"direction": "Splicore-client-to-official-endpoint", "profile": profile, "mode": "auto", "selected": selected, "payload_checks": checks, "expected_failure": errorText(e), "result": "PASS", "exit": 0})
			oracleWrite(t, dir, "selection-result.json", string(result))
		})
	}
}
