package encryption

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/protocol/vless/backend"
	"github.com/ike-sh/Splicore/protocol/vless/wire"
)

var referenceUUID = [16]byte{0x78, 0x12, 0x32, 0x11, 0x12, 0x34, 0x45, 0x67, 0x89, 0x12, 0x12, 0x34, 0x56, 0x78, 0x91, 0x23}

const referenceID = "78123211-1234-4567-8912-123456789123"

func endpoint(t *testing.T, address string) access.Endpoint {
	t.Helper()
	a, e := net.ResolveTCPAddr("tcp", address)
	if e != nil {
		t.Fatal(e)
	}
	return access.Endpoint{Host: a.IP.String(), Port: uint16(a.Port)}
}

func reserveAddress(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	a := l.Addr().String()
	l.Close()
	return a
}

func referenceProcess(t *testing.T, binary, address string, config any, aesMode bool) {
	t.Helper()
	root := t.TempDir()
	data, e := json.Marshal(config)
	if e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(root, "config.json")
	if e = os.WriteFile(file, data, 0o600); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(binary, "run", "-config", file)
	var log bytes.Buffer
	cmd.Stdout = &log
	cmd.Stderr = &log
	cmd.Env = append(os.Environ(), "XRAY_CONE_DISABLED=true")
	if !aesMode {
		cmd.Env = append(cmd.Env, "GODEBUG=cpu.aes=off")
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-done
		if t.Failed() {
			t.Log(log.String())
		}
	})
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		c, e := net.DialTimeout("tcp", address, 20*time.Millisecond)
		if e == nil {
			c.Close()
			return
		}
		select {
		case <-done:
			t.Fatal("reference process exited before listening")
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("reference did not listen")
}

func socksConnection(t *testing.T, address string, target access.Endpoint) net.Conn {
	t.Helper()
	c, e := net.DialTimeout("tcp", address, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	t.Cleanup(func() { c.Close() })
	if e = writeAll(c, []byte{5, 1, 0}); e != nil {
		t.Fatal(e)
	}
	reply := make([]byte, 2)
	if _, e = io.ReadFull(c, reply); e != nil || !bytes.Equal(reply, []byte{5, 0}) {
		t.Fatal("SOCKS auth", e)
	}
	p := []byte{5, 1, 0, 1}
	p = append(p, net.ParseIP(target.Host).To4()...)
	p = append(p, byte(target.Port>>8), byte(target.Port))
	if e = writeAll(c, p); e != nil {
		t.Fatal(e)
	}
	reply = make([]byte, 10)
	if _, e = io.ReadFull(c, reply); e != nil || reply[1] != 0 {
		t.Fatal("SOCKS request", e)
	}
	return c
}

func TestPinnedReferenceRawMatrix(t *testing.T) {
	binary := os.Getenv("SPLICORE_VLESS_ENCRYPTION_REFERENCE")
	if binary == "" {
		t.Skip("pinned Xray reference is external validation only")
	}
	version, e := exec.Command(binary, "version").Output()
	if e != nil || !strings.Contains(string(version), "26.10.21") || !strings.Contains(string(version), "1b1647c") {
		t.Fatal("reference identity mismatch")
	}
	for _, direction := range []string{"client-to-xray", "xray-to-server"} {
		for _, mode := range []string{"native", "xorpub", "random"} {
			for _, auth := range []string{"x25519", "mlkem768"} {
				for _, aesMode := range []bool{true, false} {
					for _, policy := range []string{"1rtt", "0rtt"} {
						t.Run(fmt.Sprintf("%s/%s/%s/aes=%v/%s", direction, mode, auth, aesMode, policy), func(t *testing.T) {
							sc, cc := testConfigs(t, auth, mode, policy, 1)
							address := reserveAddress(t)
							listen := endpoint(t, address)
							if direction == "client-to-xray" {
								target, e := net.Listen("tcp", "127.0.0.1:0")
								if e != nil {
									t.Fatal(e)
								}
								defer target.Close()
								go func() {
									for {
										c, e := target.Accept()
										if e != nil {
											return
										}
										go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
									}
								}()
								config := map[string]any{"log": map[string]any{"loglevel": "debug"}, "inbounds": []any{map[string]any{"listen": listen.Host, "port": listen.Port, "protocol": "vless", "settings": map[string]any{"clients": []any{map[string]any{"id": referenceID}}, "decryption": sc.original}}}, "outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32"}}}}}}}
								referenceProcess(t, binary, address, config, aesMode)
								client, _ := NewClient(cc)
								client.chooseAES = func() bool { return aesMode }
								for iteration := range 2 {
									enc := connect(t, client, address)
									if enc.resumed != (policy == "0rtt" && iteration == 1) {
										t.Fatal("wrong resume path")
									}
									c, e := backend.Client(context.Background(), enc, referenceUUID, endpoint(t, target.Addr().String()), false)
									if e != nil {
										t.Fatal(e)
									}
									exchange(t, c, 100003)
									c.Close()
								}
							} else {
								l, e := net.Listen("tcp", address)
								if e != nil {
									t.Fatal(e)
								}
								server, _ := NewServer(sc)
								paths := make(chan bool, 2)
								failures := make(chan error, 2)
								var wg sync.WaitGroup
								wg.Go(func() {
									for range 2 {
										raw, e := l.Accept()
										if e != nil {
											failures <- e
											return
										}
										wg.Go(func() {
											defer raw.Close()
											raw.SetDeadline(time.Now().Add(10 * time.Second))
											enc, e := server.Handshake(context.Background(), raw)
											if e != nil {
												failures <- e
												return
											}
											if enc.aesMode != aesMode {
												failures <- fmt.Errorf("reference cipher branch mismatch")
												return
											}
											paths <- enc.resumed
											req, e := wire.ReadRequest(enc)
											if e != nil || req.UUID != referenceUUID {
												failures <- ErrHandshake
												return
											}
											body := &backend.Conn{Conn: enc, Server: true}
											_, _ = io.Copy(body, body)
										})
									}
								})
								socks := reserveAddress(t)
								se := endpoint(t, socks)
								config := map[string]any{"log": map[string]any{"loglevel": "debug"}, "inbounds": []any{map[string]any{"listen": se.Host, "port": se.Port, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}}, "outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"address": listen.Host, "port": listen.Port, "id": referenceID, "encryption": cc.original}}}}
								referenceProcess(t, binary, socks, config, aesMode)
								for iteration := range 2 {
									c := socksConnection(t, socks, access.Endpoint{Host: "127.0.0.1", Port: 12345})
									exchange(t, c, 100003)
									c.Close()
									select {
									case resumed := <-paths:
										if resumed != (policy == "0rtt" && iteration == 1) {
											t.Fatal("reference did not resume as expected")
										}
									case e := <-failures:
										t.Fatal(e)
									case <-time.After(time.Second):
										t.Fatal("missing handshake path observation")
									}
								}
								l.Close()
								wg.Wait()
								server.Close()
								select {
								case e := <-failures:
									t.Fatal(e)
								default:
								}
							}
						})
					}
				}
			}
		}
	}
}
