//go:build linux && with_gvisor

package wireguardendpoint

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func systemCPU() (total, idle, system uint64) {
	raw, _ := os.ReadFile("/proc/stat")
	fields := strings.Fields(strings.SplitN(string(raw), "\n", 2)[0])
	for i, value := range fields[1:] {
		n, _ := strconv.ParseUint(value, 10, 64)
		if i < 8 {
			total += n
		}
		if i == 2 || i == 5 || i == 6 {
			system += n
		}
		if i == 3 || i == 4 {
			idle += n
		}
	}
	return total, idle, system
}

func processCPU() float64 {
	var r unix.Rusage
	_ = unix.Getrusage(unix.RUSAGE_SELF, &r)
	return float64(r.Utime.Sec+r.Stime.Sec) + float64(r.Utime.Usec+r.Stime.Usec)/1e6
}

func processRSS() int64 {
	raw, _ := os.ReadFile("/proc/self/status")
	for line := range strings.SplitSeq(string(raw), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			n, _ := strconv.ParseInt(strings.Fields(line)[1], 10, 64)
			return n
		}
	}
	return 0
}

func TestPhase36Performance(t *testing.T) {
	requireFastpath(t)
	client, server := fastConfig(t), fastConfig(t)
	server.Addresses = []string{"10.36.0.2/32", "fd36::2/128"}
	ck, sk := wgtypes.Key(client.PrivateKey.Reveal()), wgtypes.Key(server.PrivateKey.Reveal())
	server.Peers[0].PublicKey = ck.PublicKey().String()
	server.Peers[0].AllowedIPs = []string{"10.36.0.1/32", "fd36::1/128"}
	peer := fastEndpoint(t, server, Options{})
	client.Peers[0].PublicKey = sk.PublicKey().String()
	client.Peers[0].Endpoint = net.JoinHostPort("127.0.0.1", itoa(peer.Status().ListenPort))
	for _, mode := range []E.WireGuardBackend{E.Userspace, E.Kernel} {
		client.Backend = mode
		e := fastEndpoint(t, client, Options{})
		transferTCP(t, e, "10.36.0.2")
		for _, network := range []string{"tcp", "udp"} {
			var wg sync.WaitGroup
			var count atomic.Uint64
			ready := make(chan struct{})
			failures := make(chan error, 4)
			payload := bytes.Repeat([]byte("p"), 8192)
			if network == "udp" {
				payload = payload[:1024]
			}
			target := access.Endpoint{Host: "10.36.0.2", Port: 12345}
			until := time.Now().Add(time.Second)
			cpuBefore := processCPU()
			totalBefore, idleBefore, systemBefore := systemCPU()
			peerBefore := peer.Status().Peers[0]
			start := time.Now()
			for range 4 {
				wg.Go(func() {
					<-ready
					var c net.Conn
					var p net.PacketConn
					var err error
					if network == "tcp" {
						c, err = e.DialContext(context.Background(), target)
					} else {
						p, err = e.ListenPacket(context.Background(), target)
					}
					if err != nil {
						failures <- err
						return
					}
					if c != nil {
						defer c.Close()
						_ = c.SetDeadline(time.Now().Add(5 * time.Second))
					} else {
						defer p.Close()
						_ = p.SetDeadline(time.Now().Add(5 * time.Second))
					}
					buffer := make([]byte, len(payload))
					for time.Now().Before(until) {
						if c != nil {
							_, err = c.Write(payload)
							if err == nil {
								_, err = io.ReadFull(c, buffer)
							}
						} else {
							_, err = p.WriteTo(payload, net.UDPAddrFromAddrPort(netip.MustParseAddrPort("10.36.0.2:12345")))
							if err == nil {
								var n int
								n, _, err = p.ReadFrom(buffer)
								if err == nil && n != len(payload) {
									err = fmt.Errorf("short UDP %d", n)
								}
							}
						}
						if err != nil {
							failures <- err
							return
						}
						count.Add(uint64(len(payload)))
					}
				})
			}
			close(ready)
			wg.Wait()
			close(failures)
			for err := range failures {
				t.Fatal(err)
			}
			elapsed := time.Since(start).Seconds()
			totalAfter, idleAfter, systemAfter := systemCPU()
			peerAfter := peer.Status().Peers[0]
			result := map[string]any{"backend": mode, "network": network, "payload_bytes": len(payload), "concurrency": 4, "duration_seconds": elapsed, "useful_bytes": count.Load(), "mbps": float64(count.Load()) * 8 / elapsed / 1e6, "process_cpu_seconds": processCPU() - cpuBefore, "system_kernel_percent": 100 * float64(systemAfter-systemBefore) / float64(totalAfter-totalBefore), "system_busy_percent": 100 * (1 - float64(idleAfter-idleBefore)/float64(totalAfter-totalBefore)), "rss_kib": processRSS(), "kernel_peer_rx_bytes": peerAfter.RXBytes - peerBefore.RXBytes, "kernel_peer_tx_bytes": peerAfter.TXBytes - peerBefore.TXBytes, "kernel_client_engine_absent": e.device == nil && e.stack == nil}
			raw, _ := json.Marshal(result)
			t.Log("PERFORMANCE " + string(raw))
			if count.Load() == 0 {
				t.Fatal("empty benchmark")
			}
		}
		closedStatus(t, e)
	}
}
