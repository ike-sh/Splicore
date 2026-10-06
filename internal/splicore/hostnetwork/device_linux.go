package hostnetwork

import (
	"os"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// linuxDevice owns only the raw TUN FD. Address/route ownership stays in the
// journal. Go's poller waits on this nonblocking FD; deadlines interrupt use
// without freeing an FD that the journal may still need to compensate.
type linuxDevice struct {
	file    *os.File
	name    string
	control sync.Mutex
	closed  bool
	close   sync.Once
	err     error
}

func openLinuxDevice(name string, mtu uint32) (*linuxDevice, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	ifr, err := unix.NewIfreq(name)
	if err == nil {
		ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
		err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr)
	}
	if err == nil {
		var link netlink.Link
		link, err = netlink.LinkByName(name)
		if err == nil {
			err = netlink.LinkSetMTU(link, int(mtu))
		}
	}
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	// Register with Go's poller only after TUNSETIFF: an unattached TUN FD
	// reports POLLERR and permanently poisons the poll descriptor's read state.
	file := os.NewFile(uintptr(fd), name)
	if err = file.SetDeadline(time.Time{}); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &linuxDevice{file: file, name: name}, nil
}

func (d *linuxDevice) Start() error {
	d.control.Lock()
	defer d.control.Unlock()
	if d.closed {
		return os.ErrClosed
	}
	link, err := netlink.LinkByName(d.name)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}
func (d *linuxDevice) Read(p []byte) (int, error)  { return d.file.Read(p) }
func (d *linuxDevice) Write(p []byte) (int, error) { return d.file.Write(p) }
func (d *linuxDevice) Interrupt() error            { return d.file.SetDeadline(time.Unix(1, 0)) }
func (d *linuxDevice) Close() error {
	d.close.Do(func() {
		d.control.Lock()
		defer d.control.Unlock()
		d.closed = true
		d.err = d.file.Close()
	})
	return d.err
}
