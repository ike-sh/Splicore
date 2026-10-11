// Package session owns native AnyTLS multiplexing above an established TLS socket.
package session

import (
	"context"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ike-sh/Splicore/protocol/anytls/padding"
	"github.com/ike-sh/Splicore/protocol/anytls/wire"
)

type Config struct {
	Version           int
	Padding           *padding.Scheme
	Random            padding.Random
	ClientMetadata    string
	MaxStreams        int
	MaxStreamBuffer   int
	MaxSessionBuffer  int
	OpenTimeout       time.Duration
	WriteTimeout      time.Duration
	NegotiationWait   time.Duration
	HeartbeatInterval time.Duration
	HeartbeatTimeout  time.Duration
	OnPadding         func(*padding.Scheme)
	OnAlert           func(int)
}

func (c Config) defaults() (Config, error) {
	if c.Version == 0 {
		c.Version = 2
	}
	if c.Version != 1 && c.Version != 2 {
		return c, wire.ErrProtocol
	}
	if c.Padding == nil {
		c.Padding = padding.MustDefault()
	}
	if c.Random == nil {
		c.Random = padding.SecureRandom{}
	}
	if c.MaxStreams == 0 {
		c.MaxStreams = 128
	}
	if c.MaxStreamBuffer == 0 {
		c.MaxStreamBuffer = 4 << 20
	}
	if c.MaxSessionBuffer == 0 {
		c.MaxSessionBuffer = 16 << 20
	}
	if c.OpenTimeout == 0 {
		c.OpenTimeout = 5 * time.Second
	}
	if c.WriteTimeout == 0 {
		c.WriteTimeout = 5 * time.Second
	}
	if c.NegotiationWait == 0 {
		c.NegotiationWait = 100 * time.Millisecond
	}
	if c.HeartbeatInterval == 0 {
		c.HeartbeatInterval = 30 * time.Second
	}
	if c.HeartbeatTimeout == 0 {
		c.HeartbeatTimeout = 10 * time.Second
	}
	if c.MaxStreams < 1 || c.MaxStreams > 128 || c.MaxStreamBuffer < wire.MaxPayload || c.MaxStreamBuffer > 4<<20 || c.MaxSessionBuffer < c.MaxStreamBuffer || c.MaxSessionBuffer > 16<<20 || c.OpenTimeout < time.Millisecond || c.OpenTimeout > time.Minute || c.WriteTimeout < time.Millisecond || c.WriteTimeout > time.Minute || c.NegotiationWait < time.Millisecond || c.NegotiationWait > time.Second || c.HeartbeatInterval < time.Millisecond || c.HeartbeatInterval > 10*time.Minute || c.HeartbeatTimeout < time.Millisecond || c.HeartbeatTimeout > time.Minute || len(c.ClientMetadata) > 256 || !utf8.ValidString(c.ClientMetadata) || strings.ContainsAny(c.ClientMetadata, "\r\n\x00") {
		return c, wire.ErrProtocol
	}
	return c, nil
}

func sooner(a, b time.Time) time.Time {
	if a.IsZero() || !b.IsZero() && b.Before(a) {
		return b
	}
	return a
}

// Dial is supplied by the Core adapter and includes shared TLS and underlay ownership.
type Dial func(context.Context) (net.Conn, error)
