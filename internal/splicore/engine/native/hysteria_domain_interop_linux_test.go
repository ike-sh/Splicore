//go:build linux

package native

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/protocol/hysteria2/backend"
)

// This profile observes the decoded protocol packet address before resolution.
// Only the Splicore target handler queries its private DNS fixture; neither the
// harness nor the Official client resolves the forwarding target before HY2.
func TestNativeHysteriaPinnedOfficialUDPDomain(t *testing.T) {
	root := os.Getenv("SPLICORE_HYSTERIA_EVIDENCE")
	if root == "" {
		t.Skip("explicit pinned local reference campaign required")
	}
	const id = "hysteria-REFERENCE_TO_SPLICORE-udp-domain-controlled"
	const domain = "phase28-target.test"
	const password = "SyntheticHysteriaDomainPassword"
	ref := os.Getenv("SPLICORE_HYSTERIA_REFERENCE")
	const hash = "907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691"
	if mkcpSHA(t, ref) != hash {
		t.Fatal("pinned Official reference identity")
	}
	exe, _ := os.Executable()
	var binding map[string]any
	b, err := os.ReadFile(os.Getenv("SPLICORE_HYSTERIA_BINDING"))
	if err != nil || json.Unmarshal(b, &binding) != nil || binding["validation_binary_sha256"] != mkcpSHA(t, exe) {
		t.Fatal("candidate binding", err)
	}
	dir := filepath.Join(root, id)
	if err = os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	var mu sync.Mutex
	var queries []string
	dns, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsDone := make(chan struct{})
	go func() {
		defer close(dnsDone)
		buf := make([]byte, 4096)
		for {
			n, addr, err := dns.ReadFrom(buf)
			if err != nil {
				return
			}
			var request dnsmessage.Message
			if request.Unpack(buf[:n]) != nil {
				continue
			}
			response := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true, Authoritative: true, RecursionDesired: request.RecursionDesired, RecursionAvailable: true}, Questions: request.Questions}
			for _, q := range request.Questions {
				mu.Lock()
				queries = append(queries, q.Name.String())
				mu.Unlock()
				if q.Name.String() != domain+"." {
					response.Header.RCode = dnsmessage.RCodeNameError
					continue
				}
				if q.Type == dnsmessage.TypeA {
					response.Answers = append(response.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 0}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}})
				}
			}
			if raw, err := response.Pack(); err == nil {
				_, _ = dns.WriteTo(raw, addr)
			}
		}
	}()
	t.Cleanup(func() { dns.Close(); <-dnsDone })
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, ignored string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp4", dns.LocalAddr().String())
	}}
	target, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var targetHashes []string
	targetDone := make(chan struct{})
	go func() {
		defer close(targetDone)
		buf := make([]byte, 8192)
		for {
			n, addr, err := target.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			targetHashes = append(targetHashes, hyBytesHash(buf[:n]))
			mu.Unlock()
			_, _ = target.WriteTo(buf[:n], addr)
		}
	}()
	t.Cleanup(func() { target.Close(); <-targetDone })
	_, port, _ := net.SplitHostPort(target.LocalAddr().String())
	proxyTarget := net.JoinHostPort(domain, port)
	material := testkit.TLS(t)
	pair, err := tls.LoadX509KeyPair(material.CertificateFile, material.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(dir, "ca.pem")
	if err = os.WriteFile(ca, []byte(material.CACertificate), 0600); err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proofDone := make(chan struct{})
	var proofs []map[string]any
	var handlerError error
	server, err := backend.NewServer(ctx, packet, backend.ServerConfig{
		TLS:          &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}},
		Transport:    cfg.Hysteria{Version: 2},
		Authenticate: func(p string) (string, bool) { return "DOMAIN_USER", p == password },
		TCP:          func(context.Context, string, *backend.Stream, access.Endpoint) error { return net.ErrClosed },
		UDP: func(ctx context.Context, identity string, p net.PacketConn) (err error) {
			defer func() { handlerError = err; close(proofDone) }()
			buf := make([]byte, 8192)
			for range 3 {
				n, original, err := p.ReadFrom(buf)
				if err != nil {
					return err
				}
				dst, err := netaddr.From(original)
				if err != nil || dst.Host != domain || net.ParseIP(dst.Host) != nil || strconv.Itoa(int(dst.Port)) != port {
					return fmt.Errorf("not a decoded DOMAIN target: %v %v", original, err)
				}
				ips, err := resolver.LookupNetIP(ctx, "ip4", dst.Host)
				if err != nil || len(ips) != 1 || ips[0].String() != "127.0.0.1" {
					return fmt.Errorf("controlled resolution: %v %v", ips, err)
				}
				c, err := (&net.Dialer{}).DialContext(ctx, "udp4", net.JoinHostPort(ips[0].String(), port))
				if err != nil {
					return err
				}
				c.SetDeadline(time.Now().Add(5 * time.Second))
				requestHash := hyBytesHash(buf[:n])
				if _, err = c.Write(buf[:n]); err != nil {
					c.Close()
					return err
				}
				n, err = c.Read(buf)
				c.Close()
				if err != nil || hyBytesHash(buf[:n]) != requestHash {
					return fmt.Errorf("controlled target integrity: %v", err)
				}
				if _, err = p.WriteTo(buf[:n], original); err != nil {
					return err
				}
				proofs = append(proofs, map[string]any{"parsed_proxy_target": original.String(), "target_address_type": "DOMAIN", "parsed_before_resolution": true, "resolved_IP": ips[0].String(), "resolver_source": dns.LocalAddr().String(), "auth_identity": identity, "request_sha256": requestHash, "response_sha256": hyBytesHash(buf[:n]), "bytes": n})
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	server.Start()
	t.Cleanup(func() { server.Close(context.Background()) })
	doc := map[string]any{"server": server.Addr().String(), "auth": password, "tls": map[string]any{"sni": material.ServerName, "ca": ca}, "socks5": map[string]any{"listen": "127.0.0.1:0"}, "udpForwarding": []any{map[string]any{"listen": "127.0.0.1:0", "remote": proxyTarget}}}
	hyStart(t, ref, "hysteria", dir, "client", doc, "tcp", 0, "127.0.0.1")
	forward, ok := hyOwnedAddress(hyReferencePID(t, dir, "client"), "udp", 0, "127.0.0.1")
	if !ok {
		t.Fatal("owned reference forwarding socket absent")
	}
	c, err := net.Dial("udp4", forward)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	rows := hyUDP(t, func(b []byte) error { _, err := c.Write(b); return err }, c.Read, 4048)
	select {
	case <-proofDone:
	case <-ctx.Done():
		t.Fatal("protocol observation timeout")
	}
	if handlerError != nil || len(proofs) != 3 {
		t.Fatal("protocol observation", handlerError, proofs)
	}
	mu.Lock()
	queryCopy, hashCopy := append([]string(nil), queries...), append([]string(nil), targetHashes...)
	mu.Unlock()
	if len(queryCopy) == 0 || len(hashCopy) != len(rows) {
		t.Fatal("missing resolver/target evidence", queryCopy, hashCopy)
	}
	for i, row := range rows {
		if row["source_sha256"] != hashCopy[i] || row["source_sha256"] != proofs[i]["request_sha256"] {
			t.Fatal("payload proof association", i)
		}
		row["profile_id"], row["check_index"] = id, i
		row["direction"], row["network"] = "REFERENCE_TO_SPLICORE", "udp"
		row["proxy_target"], row["target_address_type"] = proxyTarget, "DOMAIN"
	}
	record := map[string]any{"profile_id": id, "reference_kind": "hysteria", "reference_tag": "app/v2.13.0", "reference_commit": "ca8fbd874fd6ca82413948de6dc5924405e103e1", "reference_sha256": hash, "reference": "OFFICIAL_HYSTERIA", "direction": "REFERENCE_TO_SPLICORE", "server_address": server.Addr().String(), "server_address_type": "IPv4", "proxy_target": proxyTarget, "target_address_type": "DOMAIN", "resolver_source": "controlled local DNS fixture", "resolver_address": dns.LocalAddr().String(), "DNS_queries": queryCopy, "protocol_parse_proofs": proofs, "controlled_target_received_hashes": hashCopy, "payloads": rows, "result": "PASS", "transport_mode": "specialized Hysteria2/QUIC/TLS1.3/h3", "auth_identity": "DOMAIN_USER", "Splicore_ports": "actual owned :0"}
	for k, v := range binding {
		record[k] = v
	}
	mkcpJSON(t, filepath.Join(dir, "result.json"), record)
}
