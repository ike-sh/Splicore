package xray

import (
	"errors"
	"net"
	"syscall"
)

// syscall.EADDRINUSE is a synthetic POSIX errno on Windows, while Winsock
// returns WSAEADDRINUSE (10048). Match the actual kernel error through wrappers.
const windowsAddressInUse = syscall.Errno(10048)
const windowsAddressUnavailable = syscall.Errno(10013)

func reserveClientListeners() (net.Listener, net.PacketConn, error) {
	return reserveWindowsClientListeners(net.Listen, net.ListenPacket)
}

// Windows allocates TCP and UDP ports independently. TCP's ephemeral range can
// include excluded UDP ports; UDP's can include active or TIME_WAIT TCP ports.
// A candidate is usable only while both reservations are held. Winsock reports
// an excluded or exclusively held port as WSAEACCES (10013). Alternate which
// kernel allocator chooses the ephemeral candidate so one protocol's exclusion
// range cannot trap the other allocator. This happens before artifact/process
// creation; exhaustion fails construction, with no traffic or child retry.
func reserveWindowsClientListeners(listen func(string, string) (net.Listener, error), packet func(string, string) (net.PacketConn, error)) (net.Listener, net.PacketConn, error) {
	var collision error
	for candidate := range 1024 {
		var tcp net.Listener
		var udp net.PacketConn
		var err error
		if candidate%2 == 0 {
			udp, err = packet("udp4", "127.0.0.1:0")
			if err != nil {
				return nil, nil, err
			}
			tcp, err = listen("tcp4", udp.LocalAddr().String())
		} else {
			tcp, err = listen("tcp4", "127.0.0.1:0")
			if err != nil {
				return nil, nil, err
			}
			udp, err = packet("udp4", tcp.Addr().String())
		}
		if err == nil {
			return tcp, udp, nil
		}
		if udp != nil {
			_ = udp.Close()
		}
		if tcp != nil {
			_ = tcp.Close()
		}
		if !errors.Is(err, windowsAddressInUse) && !errors.Is(err, windowsAddressUnavailable) {
			return nil, nil, err
		}
		collision = err
	}
	return nil, nil, collision
}
