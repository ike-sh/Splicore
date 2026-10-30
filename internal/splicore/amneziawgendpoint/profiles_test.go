//go:build with_gvisor

package amneziawgendpoint

import (
	"context"
	"net"
	"testing"
	"time"

	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func qualificationProfile(name string) E.AmneziaWG {
	c := E.AmneziaWG{Protocol: "amneziawg", Version: "3.1"}
	classic := func() {
		c.Jc, c.Jmin, c.Jmax = 3, 32, 65
		c.S1, c.S2, c.S3, c.S4 = 17, 19, 23, 29
		c.H1 = &E.AWGRange{Min: 101, Max: 109}
		c.H2 = &E.AWGRange{Min: 201, Max: 209}
		c.H3 = &E.AWGRange{Min: 301, Max: 309}
		c.H4 = &E.AWGRange{Min: 401, Max: 409}
	}
	switch name {
	case "B":
		classic()
	case "C":
		c.I1 = "<b 010203>"
		c.I2 = "<t><r 8>"
		c.I3 = "<rc 10>"
		c.I4 = "<rd 8>"
		c.I5 = "<b ff><r 4>"
		c.Jc, c.Jmin, c.Jmax = 4, 20, 40
	case "D":
		c.S1, c.S2, c.S3, c.S4 = 12, 13, 14, 15
		c.HeaderProtectionKey, _ = E.ParseSecret(E.EncodeKey([32]byte{37, 31}))
	case "E":
		c.ContentPaddingAddition = E.AWGRange{Min: 16, Max: 47}
	case "F":
		c.RekeyAfterTime = E.AWGRange{Min: 2, Max: 3}
		c.RekeyTimeout = E.AWGRange{Min: 1, Max: 1}
		c.RejectAfterTime = E.AWGRange{Min: 8, Max: 10}
		c.KeepaliveTimeout = E.AWGRange{Min: 1, Max: 2}
		c.MaxHandshakeAttempts = E.AWGRange{Min: 3, Max: 4}
	case "G":
		c.DisableCookies = true
	case "I":
		classic()
		c.HeaderProtectionKey, _ = E.ParseSecret(E.EncodeKey([32]byte{37, 31}))
		c.ContentPaddingAddition = E.AWGRange{Min: 5, Max: 19}
		c.I1 = "<b aabb><rc 12>"
		c.I3 = "<t><rd 12>"
		c.I5 = "<r 5>"
		c.DisableCookies = true
	}
	return c
}

func TestOfficialAWG31Profiles(t *testing.T) {
	testOfficialAWG31Profiles(t, E.AWGUserspace)
}

func testOfficialAWG31Profiles(t *testing.T, backend E.AmneziaWGBackend) {
	t.Helper()
	for _, name := range []string{"A", "B", "C", "D", "E", "F", "G", "I"} {
		for _, outer := range []string{"127.0.0.1", "::1"} {
			t.Run(name+"/outer-"+outer, func(t *testing.T) {
				c := qualificationProfile(name)
				c.Backend = backend
				private, public := testKeys(t)
				psk, _ := testKeys(t)
				o := startOracleProfile(t, public, []string{"10.34.0.2", "fd34::2"}, []string{"10.34.0.1/32", "fd34::1/128"}, E.EncodeKey(psk.Reveal()), 1, c)
				c.Tag = "profile-" + name
				c.PrivateKey = private
				c.Addresses = []string{"10.34.0.1/32", "fd34::1/128"}
				c.Peers = []E.WireGuardPeer{{PublicKey: o.PublicKey, PreSharedKey: psk, AllowedIPs: []string{"10.34.0.2/32", "fd34::2/128"}, Endpoint: net.JoinHostPort(outer, itoa(o.ListenPort)), PersistentKeepaliveInterval: 1}}
				e, err := New(context.Background(), c, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
				if err != nil {
					t.Fatal(err)
				}
				defer e.Close()
				if err = e.Start(context.Background()); err != nil {
					t.Fatal(err)
				}
				t.Logf("capture profile=%s outer=%s local_port=%d reference_port=%d", name, outer, e.Status().ListenPort, o.ListenPort)
				o.endpoint(t, e.Status().ListenPort)
				for _, ip := range []string{"10.34.0.2", "fd34::2"} {
					oracleTCP(t, e, ip)
					oracleUDP(t, e, ip)
				}
				for _, ip := range []string{"10.34.0.1", "fd34::1"} {
					o.dial(t, "tcp", ip, false)
					o.dial(t, "udp", ip, false)
				}
				if name == "F" {
					before := e.Status().Peers[0].LastHandshake
					time.Sleep(4 * time.Second)
					oracleUDP(t, e, "fd34::2")
					until := time.Now().Add(3 * time.Second)
					for !e.Status().Peers[0].LastHandshake.After(before) && time.Now().Before(until) {
						time.Sleep(20 * time.Millisecond)
					}
					if !e.Status().Peers[0].LastHandshake.After(before) {
						t.Fatal("custom timing did not rekey")
					}
				}
				s := e.Status()
				if s.Protocol != "amneziawg" || s.Version != "3.1" || s.Selected != backend {
					t.Fatal("protocol/backend identity collapsed")
				}
				if backend == E.AWGKernel && (e.device != nil || s.FeatureProbe != "AWG_3_1_ATTRIBUTES_VERIFIED") {
					t.Fatal("kernel qualification used a userspace engine or unprobed module")
				}
			})
		}
	}
}

func TestOfficialAWGMismatch(t *testing.T) {
	for _, kind := range []string{"HPK", "S", "H", "older-profile"} {
		t.Run(kind, func(t *testing.T) {
			c := qualificationProfile("I")
			oracleProfile := c.Clone()
			switch kind {
			case "HPK":
				oracleProfile.HeaderProtectionKey, _ = testKeys(t)
			case "S":
				oracleProfile.S1++
			case "H":
				oracleProfile.H1 = &E.AWGRange{Min: 1001, Max: 1002}
			case "older-profile":
				oracleProfile = qualificationProfile("B")
			}
			private, public := testKeys(t)
			o := startOracleProfile(t, public, []string{"10.34.0.2"}, []string{"10.34.0.1/32"}, "", 0, oracleProfile)
			c.Tag = "negative"
			c.PrivateKey = private
			c.Addresses = []string{"10.34.0.1/32"}
			c.Peers = []E.WireGuardPeer{{PublicKey: o.PublicKey, AllowedIPs: []string{"10.34.0.2/32"}, Endpoint: net.JoinHostPort("127.0.0.1", itoa(o.ListenPort))}}
			e, err := New(context.Background(), c, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			if err = e.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			o.endpoint(t, e.Status().ListenPort)
			o.dial(t, "udp", "10.34.0.1", true)
			if !e.Status().Peers[0].LastHandshake.IsZero() {
				t.Fatal("incompatible configuration authenticated")
			}
		})
	}
}
