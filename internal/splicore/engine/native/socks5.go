package native

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/engine/relay"
	"github.com/ike-sh/Splicore/internal/splicore/engine/traffic"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/address"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks5"
)

const (
	socks5HandshakeTimeout     = 10 * time.Second
	socks5ConnectTimeout       = 10 * time.Second
	socks5HandshakeLimit       = 64
	socks5SourceHandshakeLimit = 8
	socks5ConnectionLimit      = 512
)

type SOCKS5Compiler struct{}

func (SOCKS5Compiler) ProtocolID() string { return "socks5" }

func (SOCKS5Compiler) Supports(in ports.RuntimeIntent) error {
	_, err := (proxy.SOCKS5Inbound{}).BuildRuntime(context.Background(), in)
	return err
}

func (c SOCKS5Compiler) Compile(ctx context.Context, in ports.RuntimeIntent) (ports.PreparedRuntime, error) {
	if err := c.Supports(in); err != nil {
		return nil, err
	}
	settings, enabled, err := (proxy.SOCKS5Inbound{}).UDPRelay(in.Inbound)
	if err != nil {
		return nil, err
	}
	owner, err := newManagedProxyHandle(ctx, in, "SOCKS5", managedProxyLimits{
		connections: socks5ConnectionLimit, handshakes: socks5HandshakeLimit, perSource: socks5SourceHandshakeLimit,
	})
	if err != nil {
		return nil, err
	}
	h := &socks5Handle{managedProxyHandle: owner}
	if enabled {
		h.udp = newSOCKS5UDPRelay(settings)
	}
	owner.serve = h.serve
	return h, nil
}

type socks5Handle struct {
	*managedProxyHandle
	udp *socks5UDPRelay
}

func (h *socks5Handle) serve(conn net.Conn, finishHandshake func()) {
	authCtx, finishAuth := context.WithTimeout(h.ctx, socks5HandshakeTimeout)
	defer finishAuth()
	deadline, _ := authCtx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return
	}
	var user *managedProxyUser
	err := socks5.AcceptRequiredAuth(conn, conn, func(username, password string) bool {
		user = h.authenticate(authCtx, username, password)
		return user != nil
	})
	finishAuth()
	if err != nil || h.ctx.Err() != nil {
		return
	}

	emptyBind := &net.TCPAddr{IP: net.IPv4zero}
	command, target, err := socks5.ReadCommand(conn)
	if err != nil {
		if errors.Is(err, address.ErrAddress) {
			_ = socks5.Respond(conn, socks5.UnsupportedAddress, emptyBind)
		}
		return
	}
	if command == socks5.UDPAssociate && h.udp != nil {
		h.associateUDP(conn.(*net.TCPConn), target, user, finishHandshake)
		return
	}
	if command != socks5.Connect {
		_ = socks5.Respond(conn, socks5.UnsupportedCommand, emptyBind)
		return
	}
	if target.Validate() != nil {
		_ = socks5.Respond(conn, socks5.UnsupportedAddress, emptyBind)
		return
	}
	ctx, cancel := context.WithTimeout(h.ctx, socks5ConnectTimeout)
	remote, err := h.dialTarget(ctx, target)
	cancel()
	_ = conn.SetWriteDeadline(time.Now().Add(socks5HandshakeTimeout))
	if err != nil {
		reply := socks5.ErrorReply(err)
		if errors.Is(err, errProxySelfTarget) {
			reply = socks5.NotAllowed
		}
		_ = socks5.Respond(conn, reply, emptyBind)
		return
	}
	defer remote.Close()
	bind, ok := remote.LocalAddr().(*net.TCPAddr)
	if !ok {
		bind = emptyBind
	}
	if socks5.Respond(conn, socks5.Succeeded, bind) != nil || conn.SetDeadline(time.Time{}) != nil {
		return
	}
	finishHandshake()
	relay.Join(h.ctx, traffic.Conn(conn, &h.total, user.stats), remote)
}
