//go:build linux

package native

import (
	"net"
	"sync"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

// This bounded local QA fixture owns an actual UDP :0 front socket and a
// distinct connected UDP socket for each source endpoint, preserving session
// identities even when different clients use the same 16 bit token.
type mkcpImpairmentProxy struct {
	front                                   *net.UDPConn
	target                                  *net.UDPAddr
	mu                                      sync.Mutex
	peers                                   map[string]*net.UDPConn
	counts                                  [2][4]int
	held                                    [2]func()
	dataLoss, ackLoss, reorders, duplicates int
	dispatchDone                            chan struct{}
	readers                                 sync.WaitGroup
	once                                    sync.Once
}

func mkcpProxy(t *testing.T, target access.Endpoint) *mkcpImpairmentProxy {
	t.Helper()
	front, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	upstream, e := net.ResolveUDPAddr("udp4", net.JoinHostPort(target.Host, portString(target.Port)))
	if e != nil {
		front.Close()
		t.Fatal(e)
	}
	p := &mkcpImpairmentProxy{front: front, target: upstream, peers: map[string]*net.UDPConn{}, dispatchDone: make(chan struct{})}
	go p.dispatch()
	t.Cleanup(func() { p.Close() })
	return p
}
func (p *mkcpImpairmentProxy) apply(direction int, b []byte, send func([]byte)) {
	if len(b) < 4 || b[2] > 3 {
		return
	}
	packet := append([]byte(nil), b...)
	deliver := func() { send(packet) }
	p.mu.Lock()
	code := int(b[2])
	p.counts[direction][code]++
	n := p.counts[direction][code]
	if code == 1 && n == 1 {
		p.dataLoss++
		p.mu.Unlock()
		return
	}
	if code == 0 && n == 1 {
		p.ackLoss++
		p.mu.Unlock()
		return
	}
	if code == 1 && n == 4 {
		p.held[direction] = deliver
		p.reorders++
		p.mu.Unlock()
		return
	}
	held := p.held[direction]
	p.held[direction] = nil
	duplicate := code == 1 && n%7 == 0
	if duplicate {
		p.duplicates++
	}
	p.mu.Unlock()
	deliver()
	if held != nil {
		held()
	}
	if duplicate {
		deliver()
	}
}
func (p *mkcpImpairmentProxy) dispatch() {
	defer close(p.dispatchDone)
	buffer := make([]byte, 65536)
	for {
		n, client, e := p.front.ReadFromUDP(buffer)
		if e != nil {
			return
		}
		p.mu.Lock()
		peer := p.peers[client.String()]
		if peer == nil && len(p.peers) < 32 {
			peer, e = net.DialUDP("udp4", nil, p.target)
			if e == nil {
				p.peers[client.String()] = peer
				p.readers.Add(1)
				go func(upstream *net.UDPConn, client *net.UDPAddr) {
					defer p.readers.Done()
					b := make([]byte, 65536)
					for {
						n, e := upstream.Read(b)
						if e != nil {
							return
						}
						p.apply(1, b[:n], func(packet []byte) { p.front.WriteToUDP(packet, client) })
					}
				}(peer, client)
			}
		}
		p.mu.Unlock()
		if peer != nil {
			p.apply(0, buffer[:n], func(packet []byte) { peer.Write(packet) })
		}
	}
}
func (p *mkcpImpairmentProxy) Close() {
	p.once.Do(func() {
		p.front.Close()
		<-p.dispatchDone
		p.mu.Lock()
		all := make([]*net.UDPConn, 0, len(p.peers))
		for _, peer := range p.peers {
			all = append(all, peer)
		}
		p.mu.Unlock()
		for _, peer := range all {
			peer.Close()
		}
		p.readers.Wait()
	})
}
func (p *mkcpImpairmentProxy) evidence() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	return map[string]any{"scope": "loopback deterministic UDP QA fixture", "data_drops": p.dataLoss, "ack_drops": p.ackLoss, "reorders": p.reorders, "duplicates": p.duplicates, "peer_sockets": len(p.peers), "owner_loops": "joined", "front": p.front.LocalAddr().String()}
}
