//go:build linux

package native

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
)

func hyReferenceH3(t *testing.T, remote string, tc *tls.Config, auth, path string) (int, string, http.Header) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	tr := &quic.Transport{Conn: p}
	defer tr.Close()
	a, e := net.ResolveUDPAddr("udp4", remote)
	if e != nil {
		t.Fatal(e)
	}
	q, e := tr.Dial(ctx, a, tc, &quic.Config{EnableDatagrams: true})
	if e != nil {
		t.Fatal(e)
	}
	defer q.CloseWithError(0, "")
	h := &http3.Transport{}
	defer h.Close()
	client := h.NewClientConn(q)
	u, _ := url.Parse("https://hysteria" + path)
	r := (&http.Request{Method: "POST", URL: u, Header: make(http.Header)}).WithContext(ctx)
	r.Header.Set("Hysteria-Auth", auth)
	r.Header.Set("Hysteria-CC-RX", "0")
	resp, e := client.RoundTrip(r)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if e != nil {
		t.Fatal(e)
	}
	return resp.StatusCode, string(b), resp.Header
}

func hyReferenceTLS(t *testing.T, remote string, tc *tls.Config) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	tr := &quic.Transport{Conn: p}
	defer tr.Close()
	a, e := net.ResolveUDPAddr("udp4", remote)
	if e != nil {
		t.Fatal(e)
	}
	q, e := tr.Dial(ctx, a, tc, &quic.Config{})
	if q != nil {
		q.CloseWithError(0, "")
	}
	return e
}

func TestNativeHysteriaPinnedAuthMasquerade(t *testing.T) {
	root := os.Getenv("SPLICORE_HYSTERIA_EVIDENCE")
	if root == "" {
		t.Skip("explicit pinned local reference campaign required")
	}
	exe, _ := os.Executable()
	var binding map[string]any
	b, e := os.ReadFile(os.Getenv("SPLICORE_HYSTERIA_BINDING"))
	if e != nil || json.Unmarshal(b, &binding) != nil || binding["validation_binary_sha256"] != mkcpSHA(t, exe) {
		t.Fatal("binding", e)
	}
	for ki, kind := range []string{"hysteria", "xray"} {
		ref, hash, tag, commit := os.Getenv("SPLICORE_HYSTERIA_REFERENCE"), "907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691", "app/v2.13.0", "ca8fbd874fd6ca82413948de6dc5924405e103e1"
		if kind == "xray" {
			ref, hash, tag, commit = os.Getenv("SPLICORE_HYSTERIA_XRAY"), "4cca4de3ab8c16b3803a70e9ebe0570d2a72480c716d89aa91603ec568bf0f44", "v26.10.10", "701af60772cda123492f86e383e1fdba066614a9"
		}
		if mkcpSHA(t, ref) != hash {
			t.Fatal("reference identity")
		}
		for mi, mode := range []string{"404", "string", "file", "proxy"} {
			t.Run(kind+"-auth-masquerade-"+mode, func(t *testing.T) {
				id := kind + "-auth-masquerade-" + mode
				dir := filepath.Join(root, id)
				os.MkdirAll(dir, 0700)
				material := testkit.TLS(t)
				for _, f := range []struct{ source, name string }{{material.CertificateFile, "cert.pem"}, {material.PrivateKeyFile, "key.pem"}} {
					b, e := os.ReadFile(f.source)
					if e != nil {
						t.Fatal(e)
					}
					os.WriteFile(filepath.Join(dir, f.name), b, 0600)
				}
				pool := x509.NewCertPool()
				pool.AppendCertsFromPEM([]byte(material.CACertificate))
				tc := &tls.Config{RootCAs: pool, ServerName: material.ServerName, NextProtos: []string{"h3"}}
				os.WriteFile(filepath.Join(dir, "public.txt"), []byte("reference-file"), 0600)
				up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("X-Fixture", "proxy")
					io.WriteString(w, "reference-proxy")
				}))
				defer up.Close()
				var mu sync.Mutex
				var accepted []string
				auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var req struct{ Auth string }
					json.NewDecoder(r.Body).Decode(&req)
					id := ""
					if req.Auth == "AUTH_A" || req.Auth == "AUTH_B" {
						id = req.Auth
						mu.Lock()
						accepted = append(accepted, id)
						mu.Unlock()
					}
					json.NewEncoder(w).Encode(map[string]any{"ok": id != "", "id": id})
				}))
				defer auth.Close()
				var doc any
				want := 0
				if kind == "hysteria" {
					d := map[string]any{"listen": "127.0.0.1:0", "tls": map[string]any{"cert": filepath.Join(dir, "cert.pem"), "key": filepath.Join(dir, "key.pem")}, "auth": map[string]any{"type": "http", "http": map[string]any{"url": auth.URL}}}
					switch mode {
					case "string":
						d["masquerade"] = map[string]any{"type": "string", "string": map[string]any{"content": "reference-string", "statusCode": 403, "headers": map[string]string{"X-Fixture": "string"}}}
					case "file":
						d["masquerade"] = map[string]any{"type": "file", "file": map[string]any{"dir": dir}}
					case "proxy":
						d["masquerade"] = map[string]any{"type": "proxy", "proxy": map[string]any{"url": up.URL, "rewriteHost": true}}
					}
					doc = d
				} else {
					want = 42400 + ki*100 + mi
					settings := map[string]any{"version": 2}
					switch mode {
					case "string":
						settings["masquerade"] = map[string]any{"type": "string", "content": "reference-string", "statusCode": 403, "headers": map[string]string{"X-Fixture": "string"}}
					case "file":
						settings["masquerade"] = map[string]any{"type": "file", "dir": dir}
					case "proxy":
						settings["masquerade"] = map[string]any{"type": "proxy", "url": up.URL, "rewriteHost": true}
					}
					doc = map[string]any{"log": map[string]any{"loglevel": "debug"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": want, "protocol": "hysteria", "settings": map[string]any{"version": 2, "users": []any{map[string]any{"auth": "AUTH_A", "email": "synthetic-A"}, map[string]any{"auth": "AUTH_B", "email": "synthetic-B"}}}, "streamSettings": map[string]any{"network": "hysteria", "security": "tls", "hysteriaSettings": settings, "tlsSettings": map[string]any{"alpn": []string{"h3"}, "certificates": []any{map[string]any{"certificateFile": filepath.Join(dir, "cert.pem"), "keyFile": filepath.Join(dir, "key.pem")}}}}}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}
				}
				remote := hyStart(t, ref, kind, dir, "server", doc, "udp", want, "127.0.0.1")
				var tlsChecks []map[string]any
				if mode == "404" {
					for _, name := range []string{"wrong-ca", "wrong-sni", "explicit-insecure"} {
						probe := tc.Clone()
						switch name {
						case "wrong-ca":
							probe.RootCAs = x509.NewCertPool()
						case "wrong-sni":
							probe.ServerName = "wrong.synthetic.example"
						case "explicit-insecure":
							probe.RootCAs = x509.NewCertPool()
							probe.InsecureSkipVerify = true
						}
						e := hyReferenceTLS(t, remote, probe)
						if (e == nil) != (name == "explicit-insecure") {
							t.Fatal("reference TLS", name, e)
						}
						tlsChecks = append(tlsChecks, map[string]any{"profile": name, "expected_acceptance": name == "explicit-insecure", "result": "PASS"})
					}
				}
				var rows []map[string]any
				for _, authValue := range []string{"AUTH_A", "AUTH_B", "INVALID"} {
					status, body, headers := hyReferenceH3(t, remote, tc, authValue, "/auth")
					if authValue != "INVALID" {
						if status != 233 || headers.Get("Hysteria-UDP") != "true" {
							t.Fatal("valid multi-user reference auth", status, headers)
						}
					} else {
						wantStatus := 404
						wantBody := ""
						switch mode {
						case "string":
							wantStatus = 403
							wantBody = "reference-string"
						case "proxy":
							wantStatus = 200
							wantBody = "reference-proxy"
						}
						if status != wantStatus || wantBody != "" && body != wantBody || headers.Get("Hysteria-UDP") != "" {
							t.Fatal("invalid reference auth fallthrough", status, body, headers)
						}
					}
					rows = append(rows, map[string]any{"auth_identity": authValue, "path": "/auth", "status": status, "body_sha256": hyBytesHash([]byte(body)), "result": "PASS"})
				}
				path := "/ordinary"
				if mode == "file" {
					path = "/public.txt"
				}
				status, body, headers := hyReferenceH3(t, remote, tc, "INVALID", path)
				if status == 233 || headers.Get("Hysteria-UDP") != "" || mode == "file" && (status != 200 || body != "reference-file") {
					t.Fatal("ordinary reference H3", status, body)
				}
				rows = append(rows, map[string]any{"auth_identity": "NONE", "path": path, "status": status, "body_sha256": hyBytesHash([]byte(body)), "result": "PASS"})
				if kind == "hysteria" {
					mu.Lock()
					if len(accepted) != 2 || accepted[0] != "AUTH_A" || accepted[1] != "AUTH_B" {
						t.Error("official multi-user identity", accepted)
					}
					mu.Unlock()
				}
				record := map[string]any{"profile_id": id, "reference_kind": kind, "reference_tag": tag, "reference_commit": commit, "reference_sha256": hash, "direction": "H3_SPLICORE_TO_REFERENCE", "transport_mode": "Hysteria2/TLS1.3/h3", "congestion_mode": "reference default; raw client library Reno", "masquerade_mode": mode, "auth_checks": rows, "result": "PASS"}
				for k, v := range binding {
					record[k] = v
				}
				record["TLS_checks"] = tlsChecks
				record["server_address_type"] = "IPv4"
				record["server_address"] = remote
				record["target_address_type"] = "NOT_APPLICABLE"
				record["target_scope"] = "HTTP3 auth/masquerade surface; no proxy payload target"
				mkcpJSON(t, filepath.Join(dir, "result.json"), record)
			})
		}
	}
}
