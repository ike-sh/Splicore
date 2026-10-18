//go:build linux

package packet

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type nftRunner func(string) error

func nft(script string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	// Kernel/tool diagnostics can contain machine data; expose a stable action.
	if cmd.Run() != nil {
		return errors.New("Hysteria UDP range requires nftables and CAP_NET_ADMIN; verify nft is installed and grant network administration privileges")
	}
	return nil
}
func installRange(addr *net.UDPAddr, lo, hi uint16) (func() error, error) {
	return installNFT(addr, lo, hi, nft)
}
func installNFT(addr *net.UDPAddr, lo, hi uint16, run nftRunner) (func() error, error) {
	if addr == nil || addr.IP == nil || addr.Port != int(lo) || lo == 0 || hi <= lo || addr.Zone != "" {
		return nil, ErrPacket
	}
	var id [16]byte
	if _, e := rand.Read(id[:]); e != nil {
		return nil, ErrEntropy
	}
	table := fmt.Sprintf("splicore_hy2_%x", id[:])
	// Creating an empty table separately proves ownership before any rollback.
	if e := run("add table inet " + table + "\n"); e != nil {
		return nil, e
	}
	var once sync.Once
	var cleanupErr error
	cleanup := func() error {
		once.Do(func() { cleanupErr = run("delete table inet " + table + "\n") })
		return cleanupErr
	}
	family := "ip"
	if addr.IP.To4() == nil {
		family = "ip6"
	}
	scope := "meta nfproto ipv4 "
	if family == "ip6" {
		scope = "meta nfproto ipv6 "
	}
	if !addr.IP.IsUnspecified() {
		scope += family + " daddr " + addr.IP.String() + " "
	} else {
		scope += "fib daddr type local "
	}
	var b bytes.Buffer
	// Both hooks are scoped to the listener address. Output supports local peers.
	for _, hook := range []string{"prerouting", "output"} {
		fmt.Fprintf(&b, "add chain inet %s %s { type nat hook %s priority dstnat; policy accept; }\n", table, hook, hook)
		fmt.Fprintf(&b, "add rule inet %s %s %sudp dport %d-%d redirect to :%d\n", table, hook, scope, int(lo)+1, hi, lo)
	}
	if e := run(b.String()); e != nil {
		return nil, errors.Join(e, cleanup())
	}
	return cleanup, nil
}
