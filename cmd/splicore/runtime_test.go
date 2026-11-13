package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	maskcfg "github.com/ike-sh/Splicore/internal/splicore/domain/finalmask"
	"github.com/ike-sh/Splicore/internal/splicore/finalmask"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
	"github.com/ike-sh/Splicore/protocol/vless/backend"
	"github.com/ike-sh/Splicore/protocol/vless/encryption"
)

// This test must execute a separately built product binary. It does not replace
// Serve, storage, the control channel, or the proxy with a test implementation.
func TestRuntimeBinaryTrafficShutdownAndRestart(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, masked := range []bool{false, true} {
			name := "plain"
			if encrypted {
				name = "encrypted"
			}
			if masked {
				name += "-native-sudoku"
			}
			t.Run(name, func(t *testing.T) { runtimeBinaryTraffic(t, masked, encrypted) })
		}
	}
}

func runtimeBinaryTraffic(t *testing.T, masked, encrypted bool) {
	binary := os.Getenv("SPLICORE_RUNTIME_BINARY")
	if binary == "" {
		t.Skip("set SPLICORE_RUNTIME_BINARY to the native built core to run process qualification")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("native binary path must be absolute")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	dir := t.TempDir()
	bootstrap := filepath.Join(dir, "bootstrap.yaml")
	key := filepath.Join(dir, "keys", "master.key")
	control := filepath.Join(dir, "ctl", "core.sock")
	if runtime.GOOS != "windows" {
		// Subtest names can exceed sockaddr_un's path bound. Keep the real
		// control socket in a separate, short, private temporary directory.
		controlRoot, err := os.MkdirTemp(os.TempDir(), "sp-ctl-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(controlRoot); err != nil {
				t.Error(err)
			}
		})
		control = filepath.Join(controlRoot, "core.sock")
	}
	state := filepath.Join(dir, "state")
	config := fmt.Sprintf("schema: 1\nstate_directory: %s\nkey_file: %s\napi:\n  unix_socket: %s\n", filepath.ToSlash(state), filepath.ToSlash(key), filepath.ToSlash(control))
	if err := os.WriteFile(bootstrap, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	runCLI := func(args ...string) []byte {
		t.Helper()
		out, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("CLI %v: %v: %s", args, err, out)
		}
		return out
	}
	var version struct {
		Commit, Platform, CGOEnabled string
		BuildTags                    string `json:"build_tags"`
	}
	versionRaw := runCLI("version", "--json")
	if json.Unmarshal(versionRaw, &version) != nil {
		t.Fatal("invalid version JSON")
	}
	if !bytes.Contains(versionRaw, []byte(`"cgo_enabled":"0"`)) || !strings.Contains(string(versionRaw), runtime.GOOS+"/"+runtime.GOARCH) {
		t.Fatal("incorrect native build metadata:", string(versionRaw))
	}
	if !bytes.Contains(runCLI("help"), []byte("splicore run")) {
		t.Fatal("missing offline help")
	}
	runCLI("key", "init", "--file", key)
	// Key provisioning never replaces the existing vault identity.
	if err := exec.CommandContext(ctx, binary, "key", "init", "--file", key).Run(); err == nil {
		t.Fatal("key init overwrote existing identity")
	}
	runCLI("check", "--config", bootstrap)
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("fresh check created state")
	}
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	// The daemon cannot inherit this test's probe socket. Use the shared
	// cross-package lease outside ephemeral client ports until child cleanup.
	proxyPort := testkit.PeerPort(t, "tcp")
	proxyAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort))
	user := "c60224f4-8ee9-4f3e-a605-5af746b89fe8"
	document := filepath.Join(dir, "vless.json")
	draft := fmt.Sprintf(`{"schema":1,"name":"runtime-e2e","listener":{"host":"127.0.0.1","port":%d},"display_endpoint":{"host":"127.0.0.1","port":%d},"settings":{"security":"none","flow":"none","transport":"tcp","packet_encoding":"xudp"},"users":[{"account_name":"runtime-user","uuid":"%s"}]}`, proxyPort, proxyPort, user)
	var encryptionConfig *encryption.Config
	var serverDecryption string
	if encrypted {
		var public string
		serverDecryption, public, err = encryption.Generate("mlkem768", "random", "0rtt", "600s", "100-35-35")
		if err != nil {
			t.Fatal(err)
		}
		encryptionConfig, err = encryption.ParseClient(public)
		if err != nil {
			t.Fatal(err)
		}
		draft = strings.Replace(draft, `"users":`, `"server_secret":{"decryption":"`+serverDecryption+`"},"users":`, 1)
	}
	var mask *maskcfg.Config
	if masked {
		rawMask := `{"tcp":[{"type":"sudoku","settings":{"password":"synthetic-native-table","ascii":"prefer_entropy","paddingMin":10,"paddingMax":40}}]}`
		mask = new(maskcfg.Config)
		if err := json.Unmarshal([]byte(rawMask), mask); err != nil {
			t.Fatal(err)
		}
		draft = strings.Replace(draft, `"packet_encoding":"xudp"`, `"packet_encoding":"xudp","stream_transport":{"kind":"tcp","final_mask":`+rawMask+`}`, 1)
	}
	if err := os.WriteFile(document, []byte(draft), 0600); err != nil {
		t.Fatal(err)
	}
	runCLI("check", "--config", bootstrap, "--protocol", "vless", "--file", document)
	badDocument := filepath.Join(dir, "invalid-vless.json")
	if err := os.WriteFile(badDocument, []byte(strings.Replace(draft, `"port":`+strconv.Itoa(proxyPort), `"port":0`, 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := exec.CommandContext(ctx, binary, "check", "--config", bootstrap, "--protocol", "vless", "--file", badDocument).Run(); err == nil {
		t.Fatal("check accepted invalid protocol port")
	}
	probe, err := net.Listen("tcp4", proxyAddress)
	if err != nil {
		t.Fatal("check bound a listener:", err)
	}
	probe.Close()
	client := transport.UnixClient(control)
	defer client.Close()
	for iteration := 0; iteration < 2; iteration++ {
		logPath := filepath.Join(dir, fmt.Sprintf("core-%d.log", iteration))
		log, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binary, "run", "--config", bootstrap)
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Start(); err != nil {
			log.Close()
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		joined := false
		t.Cleanup(func() {
			if !joined {
				_ = cmd.Process.Kill()
				<-done
			}
			log.Close()
		})
		deadline := time.Now().Add(5 * time.Second)
		for {
			_, err := client.System(ctx)
			if err == nil {
				break
			}
			select {
			case exited := <-done:
				joined = true
				data, _ := os.ReadFile(logPath)
				t.Fatalf("core exited before Ready: %v: %s", exited, data)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatal("core not ready:", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
		runCLI("status", "--config", bootstrap)
		if iteration == 0 {
			planPath := filepath.Join(dir, "plan.json")
			plan := runCLI("inbound", "plan", "--config", bootstrap, "--protocol", "vless", "--file", document)
			if err := os.WriteFile(planPath, plan, 0600); err != nil {
				t.Fatal(err)
			}
			runCLI("inbound", "apply", "--config", bootstrap, "--protocol", "vless", "--file", document, "--plan", planPath)
		}
		runCLI("check", "--config", bootstrap)
		var encryptionClient *encryption.Client
		if encrypted {
			encryptionClient, err = encryption.NewClient(encryptionConfig)
			if err != nil {
				t.Fatal(err)
			}
		}
		raw, err := (&net.Dialer{}).DialContext(ctx, "tcp4", proxyAddress)
		if err != nil {
			t.Fatal("real VLESS listener unavailable:", err)
		}
		raw, err = finalmask.Wrap(raw, mask, false)
		if err != nil {
			t.Fatal(err)
		}
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		if encrypted {
			raw, err = encryptionClient.Handshake(ctx, raw)
			if err != nil {
				t.Fatal(err)
			}
		}
		id, _ := uuid.FromString(user)
		host, portText, _ := net.SplitHostPort(echo.Addr().String())
		port, _ := strconv.Atoi(portText)
		proxied, err := backend.Client(ctx, raw, [16]byte(id), access.Endpoint{Host: host, Port: uint16(port)}, false)
		if err != nil {
			raw.Close()
			t.Fatal(err)
		}
		payload := bytes.Repeat([]byte{0, 1, 2, 3, 250, 251, 252, 255}, 4096)
		if _, err := proxied.Write(payload); err != nil {
			proxied.Close()
			t.Fatal(err)
		}
		actual := make([]byte, len(payload))
		if _, err := io.ReadFull(proxied, actual); err != nil || !bytes.Equal(payload, actual) {
			proxied.Close()
			t.Fatal("real proxy payload mismatch:", err)
		}
		t.Logf("native %s/%s pid=%d iteration=%d VLESS TCP loopback echo bytes=%d sha256=%x", runtime.GOOS, runtime.GOARCH, cmd.Process.Pid, iteration, len(payload), sha256.Sum256(actual))
		unauthenticated, err := net.DialTimeout("tcp4", proxyAddress, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		unauthenticated, err = finalmask.Wrap(unauthenticated, mask, false)
		if err != nil {
			t.Fatal(err)
		}
		_ = unauthenticated.SetDeadline(time.Now().Add(3 * time.Second))
		if encrypted {
			unauthenticated, err = encryptionClient.Handshake(ctx, unauthenticated)
			if err != nil {
				t.Fatal("resumed channel before UUID rejection:", err)
			}
		}
		wrongID := [16]byte(id)
		wrongID[0] ^= 0x55
		denied, err := backend.Client(ctx, unauthenticated, wrongID, access.Endpoint{Host: host, Port: uint16(port)}, false)
		if err == nil {
			_, _ = denied.Write([]byte("must-not-relay"))
			n, deniedErr := denied.Read(make([]byte, 32))
			if n != 0 || deniedErr == nil {
				denied.Close()
				t.Fatal("unauthenticated VLESS client relayed data")
			}
			if timeout, ok := deniedErr.(net.Error); ok && timeout.Timeout() {
				denied.Close()
				t.Fatal("unauthenticated session was not closed")
			}
			denied.Close()
		} else {
			unauthenticated.Close()
		}
		// Retain the live proxy stream while stopping to exercise connection joins.
		if runtime.GOOS != "windows" && iteration == 0 {
			if err := cmd.Process.Signal(os.Interrupt); err != nil {
				t.Fatal(err)
			}
		} else {
			runCLI("stop", "--config", bootstrap)
		}
		select {
		case err := <-done:
			joined = true
			if err != nil {
				t.Fatal("unclean core exit:", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("core shutdown timed out")
		}
		_ = proxied.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := proxied.Read(make([]byte, 1)); err == nil {
			t.Fatal("shutdown retained live proxy connection")
		}
		proxied.Close()
		client.Close()
		probe, err = net.Listen("tcp4", proxyAddress)
		if err != nil {
			t.Fatal("shutdown retained listener:", err)
		}
		probe.Close()
		if encrypted {
			// The live production store must never persist the decryption string
			// in plaintext, including rollback journals or WAL sidecars.
			files, err := os.ReadDir(state)
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range files {
				if file.IsDir() {
					continue
				}
				data, err := os.ReadFile(filepath.Join(state, file.Name()))
				if err != nil || bytes.Contains(data, []byte(serverDecryption)) {
					t.Fatal("state contains plaintext decryption material or is unreadable")
				}
			}
		}
		log.Close()
		data, _ := os.ReadFile(logPath)
		if !bytes.Contains(data, []byte("Splicore ready")) {
			t.Fatal("missing initialized Ready record")
		}
		t.Logf("core exit=0, active stream closed, listener released; log: %s", data)
	}
}
