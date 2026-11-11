// Package session implements the unversioned ShadowQUIC proxy grammar over JLS v3.
package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

var (
	ErrProtocol    = errors.New("invalid ShadowQUIC framing")
	ErrAuth        = errors.New("ShadowQUIC authentication failed")
	ErrLimit       = errors.New("ShadowQUIC resource limit")
	ErrUnavailable = errors.New("ShadowQUIC requires with_quic")
)

const MaxPayload = 1200

type Limits struct {
	MaxConnections   int `json:"max_connections,omitempty"`
	MaxStreams       int `json:"max_streams,omitempty"`
	MaxFlows         int `json:"max_udp_flows,omitempty"`
	HandshakeSeconds int `json:"handshake_timeout,omitempty"`
	IdleSeconds      int `json:"idle_timeout,omitempty"`
	KeepAliveSeconds int `json:"keepalive,omitempty"`
	UDPIdleSeconds   int `json:"udp_idle_timeout,omitempty"`
}

func (l Limits) Defaults() Limits {
	if l.MaxConnections == 0 {
		l.MaxConnections = 32
	}
	if l.MaxStreams == 0 {
		l.MaxStreams = 64
	}
	if l.MaxFlows == 0 {
		l.MaxFlows = 32
	}
	if l.HandshakeSeconds == 0 {
		l.HandshakeSeconds = 5
	}
	if l.IdleSeconds == 0 {
		l.IdleSeconds = 60
	}
	if l.KeepAliveSeconds == 0 {
		l.KeepAliveSeconds = 15
	}
	if l.UDPIdleSeconds == 0 {
		l.UDPIdleSeconds = 60
	}
	return l
}

func (l Limits) Validate() error {
	l = l.Defaults()
	if l.MaxConnections < 1 || l.MaxConnections > 128 || l.MaxStreams < 1 || l.MaxStreams > 256 || l.MaxFlows < 1 || l.MaxFlows > 128 || l.HandshakeSeconds < 1 || l.HandshakeSeconds > 30 || l.IdleSeconds < 10 || l.IdleSeconds > 600 || l.KeepAliveSeconds < 1 || l.KeepAliveSeconds >= l.IdleSeconds || l.UDPIdleSeconds < 2 || l.UDPIdleSeconds > 600 {
		return ErrLimit
	}
	return nil
}

func (l Limits) Handshake() time.Duration {
	return time.Duration(l.Defaults().HandshakeSeconds) * time.Second
}

func (l Limits) UDPIdle() time.Duration {
	return time.Duration(l.Defaults().UDPIdleSeconds) * time.Second
}

type User struct{ ID, Username, Password string }

func (User) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("ShadowQUICUser{[REDACTED]}")) }

type ClientConfig struct {
	ServerName    string
	UDPOverStream bool
	User          User
	Limits        Limits
	Socket        func(context.Context) (net.PacketConn, net.Addr, error)
}
type ServerConfig struct {
	ServerName   string
	Camouflage   string
	Users        []User
	Limits       Limits
	PacketDialer func(context.Context, string, string) (net.PacketConn, net.Addr, error)
	Authorize    func(string) bool
	TCP          func(context.Context, string, net.Conn, access.Endpoint) error
	UDP          func(context.Context, string, net.PacketConn) error
}
