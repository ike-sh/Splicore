//go:build linux && with_gvisor

package wireguardendpoint

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestPhase36BirthUnderlay(t *testing.T) {
	requireFastpath(t)
	ctx := context.Background()
	remoteNS := -1
	if err := namespaceRun(ctx, -1, func() error {
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			return err
		}
		var err error
		remoteNS, err = unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(remoteNS)
	remote, err := netlink.NewHandleAt(netns.NsHandle(remoteNS), unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	lo, err := remote.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err = remote.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	link := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "sp36underlay"}, PeerName: "sp36remote"}
	if err = netlink.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(link)
	other, err := netlink.LinkByName("sp36remote")
	if err != nil {
		t.Fatal(err)
	}
	if err = netlink.LinkSetNsFd(other, remoteNS); err != nil {
		t.Fatal(err)
	}
	other, err = remote.LinkByName("sp36remote")
	if err != nil {
		t.Fatal(err)
	}
	if err = netlink.AddrAdd(link, &netlink.Addr{IPNet: ptrIPNet(netip.MustParsePrefix("192.0.2.1/30"))}); err != nil {
		t.Fatal(err)
	}
	if err = remote.AddrAdd(other, &netlink.Addr{IPNet: ptrIPNet(netip.MustParsePrefix("192.0.2.2/30"))}); err != nil {
		t.Fatal(err)
	}
	if err = netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	if err = remote.LinkSetUp(other); err != nil {
		t.Fatal(err)
	}
	client, server := fastConfig(t), fastConfig(t)
	server.Addresses = []string{"10.36.0.2/32", "fd36::2/128"}
	clientKey, serverKey := wgtypes.Key(client.PrivateKey.Reveal()), wgtypes.Key(server.PrivateKey.Reveal())
	server.Peers[0].PublicKey = clientKey.PublicKey().String()
	server.Peers[0].AllowedIPs = []string{"10.36.0.1/32", "fd36::1/128"}
	var peer *Endpoint
	err = namespaceRun(ctx, remoteNS, func() error {
		var err error
		peer, err = New(ctx, server, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New()})
		if err != nil {
			return err
		}
		return peer.Start(ctx)
	})
	if peer != nil {
		defer peer.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	client.Peers[0].PublicKey = serverKey.PublicKey().String()
	client.Peers[0].Endpoint = net.JoinHostPort("192.0.2.2", itoa(peer.Status().ListenPort))
	e := fastEndpoint(t, client, Options{})
	defer e.Close()
	transferTCP(t, e, "10.36.0.2")
	transferUDP(t, e, "fd36::2", 1200)
	linkRead, err := netlink.LinkByName(link.Attrs().Name)
	if err != nil {
		t.Fatal(err)
	}
	if linkRead.Attrs().Statistics.RxBytes == 0 || linkRead.Attrs().Statistics.TxBytes == 0 {
		t.Fatal("encrypted transport did not cross birth underlay")
	}
	k := e.backend.(*kernelBackend)
	links, err := k.links.LinkList()
	if err != nil || len(links) != 2 {
		t.Fatal("cleartext external interface")
	}
	if e.Status().BirthNamespace == peer.Status().BirthNamespace {
		t.Fatal("peer birth namespaces not distinct")
	}
	t.Logf("encrypted UDP traversed birth veth: rx=%d tx=%d; cleartext links=lo,wg; client_birth=%d peer_birth=%d client_cleartext=%d", linkRead.Attrs().Statistics.RxBytes, linkRead.Attrs().Statistics.TxBytes, e.Status().BirthNamespace, peer.Status().BirthNamespace, e.Status().Namespace)
}
