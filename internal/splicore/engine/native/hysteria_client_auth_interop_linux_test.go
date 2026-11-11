//go:build linux

package native

import (
	"bytes"
	"encoding/json"
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
)

func hyClientAuthAndConcurrency(t *testing.T, ref, kind, dir string, base any, socks string, h *hysteria2Handle, target, udpTarget access.Endpoint) map[string]any {
	t.Helper()
	clone := func(auth string, port int) map[string]any {
		b, _ := json.Marshal(base)
		var d map[string]any
		json.Unmarshal(b, &d)
		if kind == "hysteria" {
			d["auth"] = auth
		} else {
			d["inbounds"].([]any)[0].(map[string]any)["port"] = port
			d["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["hysteriaSettings"].(map[string]any)["auth"] = auth
		}
		return d
	}
	bdir := filepath.Join(dir, "auth-B")
	os.MkdirAll(bdir, 0700)
	want := 0
	if kind == "xray" {
		want = 42180
	}
	other := hyStart(t, ref, kind, bdir, "client", clone("SyntheticHysteriaPhase28Password1", want), "tcp", want, "127.0.0.1")
	addresses := []string{socks, other}
	ready := make(chan struct{}, 8)
	start := make(chan struct{})
	udpFinished := make(chan struct{}, 2)
	udpDone := make(chan struct{})
	var wg sync.WaitGroup
	before := h.Stats()
	for user, address := range addresses {
		for flow := range 4 {
			wg.Go(func() {
				c, _ := hySocks(t, address, 1, target)
				defer c.Close()
				// Xray's SOCKS success is optimistic. Prove target admission
				// with a distinct echo before counting this concurrent stream.
				prelude := []byte{byte(user), byte(flow)}
				if _, e := c.Write(prelude); e != nil {
					t.Fatal(e)
				}
				gotPrelude := make([]byte, 2)
				if _, e := io.ReadFull(c, gotPrelude); e != nil || !bytes.Equal(gotPrelude, prelude) {
					t.Fatal("reference admission prelude", e)
				}
				ready <- struct{}{}
				<-start
				payload := bytes.Repeat([]byte{byte(user), byte(flow), 0, 31}, 8192)
				sent := make(chan error, 1)
				go func() { _, e := c.Write(payload); sent <- e }()
				got := make([]byte, len(payload))
				_, e := io.ReadFull(c, got)
				we := <-sent
				if e != nil || we != nil || !bytes.Equal(got, payload) {
					t.Error("reference concurrent attributed TCP", user, flow, e, we)
				}
				<-udpDone
			})
		}
	}
	for range 8 {
		select {
		case <-ready:
		case <-time.After(10 * time.Second):
			t.Fatal("reference parallel opens")
		}
	}
	if len(h.server.Congestion()) != 2 {
		t.Fatal("reference auth pool identity", h.server.Congestion())
	}
	// Hold all eight TCP streams open while each reference client owns UDP.
	for user, address := range addresses {
		wg.Go(func() {
			defer func() { udpFinished <- struct{}{} }()
			var write func([]byte) error
			var read func([]byte) (int, error)
			var closeFlow func()
			if kind == "hysteria" {
				profileDir := dir
				if user == 1 {
					profileDir = bdir
				}
				forward, ok := hyOwnedAddress(hyReferencePID(t, profileDir, "client"), "udp", 0, "127.0.0.1")
				if !ok {
					t.Fatal("owned reference forwarding socket")
				}
				c, e := net.Dial("udp", forward)
				if e != nil {
					t.Fatal(e)
				}
				c.SetDeadline(time.Now().Add(10 * time.Second))
				write = func(b []byte) error { _, e := c.Write(b); return e }
				read = c.Read
				closeFlow = func() { c.Close() }
			} else {
				control, relay := hySocks(t, address, 3, access.Endpoint{Host: "127.0.0.1"})
				p, e := net.ListenPacket("udp4", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				p.SetDeadline(time.Now().Add(10 * time.Second))
				header := append([]byte{0, 0, 0}, hyAddress(udpTarget)...)
				write = func(b []byte) error { _, e := p.WriteTo(append(bytes.Clone(header), b...), relay); return e }
				read = func(b []byte) (int, error) {
					raw := make([]byte, 8192)
					n, _, e := p.ReadFrom(raw)
					if e != nil {
						return 0, e
					}
					if n < 10 {
						return 0, io.ErrUnexpectedEOF
					}
					return copy(b, raw[10:n]), nil
				}
				closeFlow = func() { p.Close(); control.Close() }
			}
			defer closeFlow()
			payload := bytes.Repeat([]byte{byte(user), 73}, 450)
			if e := write(payload); e != nil {
				t.Error(e)
				return
			}
			got := make([]byte, 4096)
			n, e := read(got)
			if e != nil || !bytes.Equal(payload, got[:n]) {
				t.Error("reference simultaneous UDP", e)
			}
		})
	}
	go func() { <-udpFinished; <-udpFinished; close(udpDone) }()
	close(start)
	wg.Wait()
	after := h.Stats()
	if after.Upload-before.Upload != 8*32770+2*900 || after.Download-before.Download != 8*32770+2*900 {
		t.Fatal("reference exact attribution total", before, after)
	}
	states := h.server.Congestion()
	if len(states) != 2 || states[0].Identity == states[1].Identity {
		t.Fatal("reference credential bleed", states)
	}
	invalidDir := filepath.Join(dir, "auth-invalid")
	os.MkdirAll(invalidDir, 0700)
	bad := clone("INVALID_SYNTHETIC", 42190)
	if kind == "hysteria" {
		path := filepath.Join(invalidDir, "client-config.json")
		mkcpJSON(t, path, bad)
		log, e := os.Create(filepath.Join(invalidDir, "client-reference.log"))
		if e != nil {
			t.Fatal(e)
		}
		cmd := exec.Command(ref, "client", "-c", path, "--disable-update-check")
		cmd.Stdout = log
		cmd.Stderr = log
		if e = cmd.Start(); e != nil {
			t.Fatal(e)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case e = <-done:
		case <-time.After(10 * time.Second):
			cmd.Process.Kill()
			<-done
			log.Close()
			t.Fatal("invalid official auth did not fail")
		}
		log.Close()
		b, _ := os.ReadFile(filepath.Join(invalidDir, "client-reference.log"))
		if e == nil || !strings.Contains(strings.ToLower(string(b)), "auth") {
			t.Fatal("invalid official reference auth", e, string(b))
		}
		mkcpJSON(t, filepath.Join(invalidDir, "client-cleanup.json"), map[string]any{"pid": cmd.Process.Pid, "wait_joined": true, "forced_kill": false, "exit_code": cmd.ProcessState.ExitCode()})
	} else {
		badSocks := hyStart(t, ref, kind, invalidDir, "client", bad, "tcp", 42190, "127.0.0.1")
		c, e := net.DialTimeout("tcp", badSocks, 5*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		c.Write([]byte{5, 1, 0})
		method := make([]byte, 2)
		if _, e = io.ReadFull(c, method); e != nil {
			t.Fatal(e)
		}
		c.Write(append([]byte{5, 1, 0}, hyAddress(target)...))
		reply := make([]byte, 4)
		n, e := io.ReadFull(c, reply)
		if e == nil && n == 4 && reply[1] == 0 {
			payload := []byte("INVALID_AUTH_MUST_NOT_REACH_TARGET")
			if _, e = c.Write(payload); e == nil {
				got := make([]byte, len(payload))
				if _, e = io.ReadFull(c, got); e == nil {
					t.Fatal("invalid Xray credential dispatched payload")
				}
			}
		}
	}
	if h.Stats().Upload != after.Upload || h.Stats().Download != after.Download {
		t.Fatal("invalid reference auth target traffic")
	}
	return map[string]any{"parallel_TCP": 8, "TCP_admission_prelude_bytes_per_stream": 2, "simultaneous_UDP": 2, "auth_identities": states, "invalid_auth": "DENIED", "invalid_auth_payload_delta": 0, "upload_delta": after.Upload - before.Upload, "download_delta": after.Download - before.Download, "result": "PASS"}
}
