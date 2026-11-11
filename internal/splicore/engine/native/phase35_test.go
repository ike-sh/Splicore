//go:build with_quic && with_utls

package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	vl "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func phase35Intent(in ports.RuntimeIntent, n client.RemoteNode) ports.RuntimeIntent {
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(in.Inbound.Settings.Data, &fields)
	fields["alpn"], _ = json.Marshal(n.Security.TLS.ALPN)
	fields["stream_transport"], _ = json.Marshal(n.Transport)
	in.Inbound.Settings.Data, _ = json.Marshal(fields)
	in.Inbound.Listeners[0].Transport = "tcp"
	if n.Transport.XHTTPH3(n.Security.TLS.ALPN) {
		in.Inbound.Listeners[0].Transport = "udp"
	}
	return in
}

func TestPhase35PinnedH3Tuning(t *testing.T) {
	binary := phase33Reference(t)
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	tcp := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	udp := trojanUDP(t)
	for _, host := range []string{"127.0.0.1", "::1"} {
		for _, direction := range []string{"splicore-client", "splicore-server"} {
			t.Run(host+"/"+direction, func(t *testing.T) {
				in, n, credential := phase33Intent(t, "vless", "packet-up")
				n.Transport.H3 = &cfg.H3{DisableChromeParrot: true, InitialStreamWindow: 65536, MaxStreamWindow: 8 << 20, InitialConnectionWindow: 524288, MaxConnectionWindow: 32 << 20, MaxIncomingStreams: 64, MaxIdleTimeout: 30, KeepAlivePeriod: 2, DisableGSO: true, DisablePathMTUDiscovery: true}
				in = phase35Intent(in, n)
				n.Endpoint.Host = host
				if direction == "splicore-server" {
					_, n.Endpoint = startMKCP(t, ctx, "vless", in, host)
				}
				socks := phase33SOCKS(t)
				peer := phase33PeerConfig(t, "vless", direction, in, n, credential, socks)
				if direction == "splicore-client" {
					inbound := peer["inbounds"].([]any)[0].(map[string]any)
					inbound["listen"] = host
					stream := inbound["streamSettings"].(map[string]any)
					stream["finalmask"] = map[string]any{"quicParams": n.Transport.H3}
				}
				phase33Peer(t, binary, peer, direction == "splicore-client")
				if direction == "splicore-client" {
					d := sharedBuild(t, ctx, n, credential)
					defer d.Close()
					sharedPayload(t, d, tcp, udp)
				} else {
					sharedExternalPayload(t, socks, tcp, udp)
				}
			})
		}
	}
}

func phase35Proxy(t *testing.T, in ports.RuntimeIntent, n client.RemoteNode, backend string) (access.Endpoint, string) {
	t.Helper()
	binary := os.Getenv("SPLICORE_PHASE35_H3_PROXY")
	if binary == "" {
		t.Skip("explicit external H3 translation fixture required")
	}
	b, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != "86bdf32b000bf13649b868dc7a8080a12e4a51753c108dd88c9ff1365820e074" {
		t.Fatal("external proxy fixture digest")
	}
	s, err := vl.Decode(in.Inbound.Settings.Data)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if external := os.Getenv("SPLICORE_PHASE35_PROXY_LOGS"); external != "" {
		root = filepath.Join(external, strings.ReplaceAll(t.Name(), "/", "-"))
		if err = os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	ca := filepath.Join(root, "ca.pem")
	if err = os.WriteFile(ca, []byte(n.Security.TLS.CACertificate), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(root, "proxy.log")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-origin", net.JoinHostPort(n.Endpoint.Host, portString(n.Endpoint.Port)), "-sni", n.Security.TLS.ServerName, "-cert", s.TLS.CertificateFile, "-key", s.TLS.PrivateKeyFile, "-ca", ca, "-backend", backend)
	cmd.Stdout, cmd.Stderr = f, f
	if err = cmd.Start(); err != nil {
		f.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); _ = f.Close() })
	for until := time.Now().Add(5 * time.Second); time.Now().Before(until); {
		data, _ := os.ReadFile(logPath)
		for line := range strings.SplitSeq(string(data), "\n") {
			if addr, ok := strings.CutPrefix(line, "READY "); ok {
				a, err := net.ResolveUDPAddr("udp", addr)
				if err != nil {
					t.Fatal(err)
				}
				return netaddrEndpoint(a), logPath
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("external proxy startup timeout")
	return access.Endpoint{}, logPath
}

func TestPhase35PinnedH3TranslationAndSplit(t *testing.T) {
	if os.Getenv("SPLICORE_PHASE35_H3_PROXY") == "" {
		t.Skip("external translation campaign required")
	}
	binary := phase33Reference(t)
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	tcp := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	udp := trojanUDP(t)
	for _, backend := range []string{"h1", "h2"} {
		for _, direction := range []string{"splicore-client", "splicore-server"} {
			for _, mode := range []string{"auto", "packet-up", "stream-up", "stream-one"} {
				if backend == "h1" && mode == "stream-one" {
					continue
				}
				t.Run(backend+"/"+direction+"/"+mode, func(t *testing.T) {
					phase35ProxyCase(t, binary, ctx, tcp, udp, backend, direction, mode, "h3", "")
				})
			}
		}
	}
	for _, direction := range []string{"splicore-client", "splicore-server"} {
		for _, legs := range [][2]string{{"h3", "http/1.1"}, {"http/1.1", "h3"}, {"h3", "h2"}, {"h2", "h3"}} {
			for _, mode := range []string{"auto", "packet-up", "stream-up"} {
				t.Run(fmt.Sprintf("split/%s/%s-%s/%s", direction, legs[0], legs[1], mode), func(t *testing.T) {
					phase35ProxyCase(t, binary, ctx, tcp, udp, "h2", direction, mode, legs[0], legs[1])
				})
			}
		}
	}
}

func phase35ProxyCase(t *testing.T, binary string, ctx context.Context, tcp, udp access.Endpoint, backend, direction, mode, upload, download string) {
	t.Helper()
	in, n, credential := phase33Intent(t, "vless", mode)
	originALPN := "h2"
	if backend == "h1" {
		originALPN = "http/1.1"
	}
	n.Security.TLS.ALPN = []string{originALPN}
	in = phase35Intent(in, n)
	if direction == "splicore-server" {
		_, n.Endpoint = startMKCP(t, ctx, "vless", in, "127.0.0.1")
	} else {
		serverNode := n
		serverNode.Transport = n.Transport.Clone()
		if backend == "h1" && mode == "stream-up" {
			// Xray's response keepalive competes with H1 body reads. Its
			// documented negative sentinel disables this server-only writer.
			serverNode.Transport.XHTTP.KeepAlive = cfg.Range{Min: -1, Max: -1}
		}
		peer := phase33PeerConfig(t, "vless", direction, in, serverNode, credential, phase33SOCKS(t))
		stream := peer["inbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
		stream["tlsSettings"].(map[string]any)["alpn"] = []string{originALPN}
		phase33Peer(t, binary, peer, false)
	}
	front, logPath := phase35Proxy(t, in, n, backend)
	n.Endpoint = front
	n.Security.TLS.ALPN = []string{upload}
	if download != "" {
		n.Transport.XHTTP.Download = &cfg.Download{Endpoint: front, Transport: cfg.Config{Kind: "xhttp", Path: n.Transport.Path, Host: n.Transport.Host}, Security: "tls", TLS: n.Security.TLS}
		n.Transport.XHTTP.Download.TLS.ALPN = []string{download}
	}
	if direction == "splicore-client" {
		d := sharedBuild(t, ctx, n, credential)
		defer d.Close()
		sharedPayload(t, d, tcp, udp)
	} else {
		socks := phase33SOCKS(t)
		phase33Peer(t, binary, phase33PeerConfig(t, "vless", direction, in, n, credential, socks), false)
		sharedExternalPayload(t, socks, tcp, udp)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"proto=HTTP/3.0", "sni=" + n.Security.TLS.ServerName, "host=" + n.Transport.Host, "path=" + n.Transport.Path, "ORIGIN proto=HTTP/" + map[string]string{"h1": "1.1", "h2": "2.0"}[backend]} {
		if !bytes.Contains(data, []byte(want)) {
			t.Fatal("translation observation absent", want)
		}
	}
	if download != "" && (!bytes.Contains(data, []byte("proto=HTTP/"+map[string]string{"http/1.1": "1.1", "h2": "2.0", "h3": "3.0"}[map[bool]string{true: download, false: upload}[upload == "h3"]]))) {
		t.Fatal("split carrier absent")
	}
}

// The external Xray client establishes the same boundary observed with the
// native client: the default response keepalive competes with HTTP/1 uploads.
// The positive matrix disables that writer with scStreamUpServerSecs=-1.
func TestPhase35PinnedH1StreamingBoundary(t *testing.T) {
	if os.Getenv("SPLICORE_PHASE35_H3_PROXY") == "" {
		t.Skip("external translation campaign required")
	}
	binary := phase33Reference(t)
	in, n, credential := phase33Intent(t, "vless", "stream-up")
	n.Security.TLS.ALPN = []string{"http/1.1"}
	in = phase35Intent(in, n)
	peer := phase33PeerConfig(t, "vless", "splicore-client", in, n, credential, phase33SOCKS(t))
	stream := peer["inbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
	stream["tlsSettings"].(map[string]any)["alpn"] = []string{"http/1.1"}
	phase33Peer(t, binary, peer, false)
	front, logPath := phase35Proxy(t, in, n, "h1")
	n.Endpoint = front
	n.Security.TLS.ALPN = []string{"h3"}
	socks := phase33SOCKS(t)
	phase33Peer(t, binary, phase33PeerConfig(t, "vless", "splicore-server", in, n, credential, socks), false)
	dst := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	c, err := phaseSOCKS(socks, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	want := bytes.Repeat([]byte("HTTP1 streaming boundary"), 7000)
	done := make(chan error, 1)
	go func() { _, err := c.Write(want); done <- err }()
	got := make([]byte, len(want))
	_, err = io.ReadFull(c, got)
	_ = c.Close()
	<-done
	if err == nil {
		t.Fatal("official HTTP/1 default keepalive boundary changed")
	}
	data, _ := os.ReadFile(logPath)
	if !bytes.Contains(data, []byte("proto=HTTP/3.0")) {
		t.Fatal("boundary failed before H3 request")
	}
	t.Log("pinned official client + official H1 origin: default response keepalive blocks interactive stream-up; positive matrix disables it")
}
