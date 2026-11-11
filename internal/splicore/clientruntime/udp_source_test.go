package clientruntime

import (
	"context"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"net"
	"testing"
	"time"
)

func TestSOCKSUDPRequestedSourceOwnership(t *testing.T) {
	m, state, _, echo := udpFixture(t)
	if c, _, err := udpControl(state, testfixture.Endpoint("127.0.0.2:1234")); err == nil {
		_ = c.Close()
		t.Fatal("foreign requested source accepted")
	}
	owner, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	control, relay, err := udpControl(state, testfixture.Endpoint((owner.LocalAddr()).String()))
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	foreign, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	frame, _ := encodeUDPPacket(echo.LocalAddr(), []byte("foreign-first"))
	_, _ = foreign.WriteToUDP(frame, netaddr.UDP(relay).(*net.UDPAddr))
	if err = udpRoundtrip(owner, relay, echo.LocalAddr(), []byte("requested-owner")); err != nil {
		t.Fatal(err)
	}
	_ = foreign.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err = foreign.ReadFromUDP(make([]byte, 1024)); err == nil {
		t.Fatal("fixed source port bypassed")
	}
	_ = control.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = m.WaitIdle(ctx); err != nil {
		t.Fatal(err)
	}
}
