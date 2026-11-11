//go:build linux

package packet

import (
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
)

func TestNFTOwnershipRollbackIPv4IPv6(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "0.0.0.0", "::"} {
		t.Run(host, func(t *testing.T) {
			var commands []string
			run := func(s string) error { commands = append(commands, s); return nil }
			clean, e := installNFT(&net.UDPAddr{IP: net.ParseIP(host), Port: 65534}, 65534, 65535, run)
			if e != nil {
				t.Fatal(e)
			}
			clean()
			clean()
			if len(commands) != 3 || !strings.Contains(commands[1], "udp dport 65535-65535 redirect to :65534") {
				t.Fatal(commands)
			}
			table := strings.Fields(commands[0])[3]
			if commands[2] != "delete table inet "+table+"\n" {
				t.Fatal("ownership")
			}
			if strings.Contains(commands[1], "flush") {
				t.Fatal("destructive command")
			}
		})
	}
	sentinel := errors.New("injected setup failure")
	for fail := 1; fail <= 2; fail++ {
		var commands []string
		_, e := installNFT(peer, 1234, 1235, func(s string) error {
			commands = append(commands, s)
			if len(commands) == fail {
				return sentinel
			}
			return nil
		})
		if !errors.Is(e, sentinel) {
			t.Fatal(e)
		}
		want := 1
		if fail == 2 {
			want = 3
		}
		if len(commands) != want {
			t.Fatal("rollback", commands)
		}
	}
}
func TestNFTConcurrentInstanceOwnership(t *testing.T) {
	var mu sync.Mutex
	owned := map[string]bool{}
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var calls []string
			clean, e := installNFT(peer, 1234, 1235, func(s string) error { calls = append(calls, s); return nil })
			if e != nil {
				t.Error(e)
				return
			}
			table := strings.Fields(calls[0])[3]
			mu.Lock()
			if owned[table] {
				t.Error("shared table")
			}
			owned[table] = true
			mu.Unlock()
			clean()
			if !strings.Contains(calls[2], table) {
				t.Error("deleted sibling")
			}
		}()
	}
	wg.Wait()
}
