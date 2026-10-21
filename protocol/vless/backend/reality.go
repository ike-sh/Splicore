//go:build with_utls

package backend

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"time"
)

var errReality = errors.New("REALITY authentication failed")

// RealityServer delegates TLS/REALITY to the admitted library. Target sockets
// are injected and bounded, and parent cancellation owns both sockets.
func RealityServer(name, key string, ids []string, target access.Endpoint, dial func(context.Context, string, string) (net.Conn, error)) (func(context.Context, net.Conn) (net.Conn, error), error) {
	return RealityServerNames([]string{name}, key, ids, target, dial)
}

func RealityServerNames(names []string, key string, ids []string, target access.Endpoint, dial func(context.Context, string, string) (net.Conn, error)) (func(context.Context, net.Conn) (net.Conn, error), error) {
	if len(names) == 0 || len(names) > 16 {
		return nil, errReality
	}
	serverNames := make(map[string]bool, len(names))
	for _, name := range names {
		kind, err := access.ParseHost(name)
		if err != nil || kind != access.DNS || serverNames[name] {
			return nil, errReality
		}
		serverNames[name] = true
	}
	private, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil || len(private) != 32 {
		return nil, errReality
	}
	shortIDs := map[[8]byte]bool{}
	for _, value := range ids {
		b, err := hex.DecodeString(value)
		if err != nil || len(b) > 8 {
			return nil, errReality
		}
		var id [8]byte
		copy(id[:], b)
		shortIDs[id] = true
	}
	if len(shortIDs) == 0 {
		shortIDs[[8]byte{}] = true
	}
	config := &utls.RealityConfig{Config: utls.Config{ServerName: names[0], MinVersion: utls.VersionTLS13, SessionTicketsDisabled: true}, Type: "tcp", Dest: net.JoinHostPort(target.Host, portString(target.Port)), PrivateKey: private, ServerNames: serverNames, ShortIds: shortIDs}
	return func(ctx context.Context, c net.Conn) (net.Conn, error) {
		local := config.Clone()
		callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var owned atomic.Pointer[realityTarget]
		local.DialContext = func(_ context.Context, network, address string) (net.Conn, error) {
			target, err := dial(callCtx, network, address)
			if err != nil {
				return nil, err
			}
			_ = target.SetDeadline(time.Now().Add(5 * time.Second))
			owned.Store(&realityTarget{target})
			if callCtx.Err() != nil {
				_ = target.Close()
				return nil, callCtx.Err()
			}
			return target, nil
		}
		done := make(chan struct{})
		stop := context.AfterFunc(callCtx, func() {
			defer close(done)
			_ = c.Close()
			if target := owned.Load(); target != nil {
				_ = target.Close()
			}
		})
		defer func() {
			if !stop() {
				<-done
			}
		}()
		result, err := utls.RealityServer(callCtx, c, local)
		if target := owned.Load(); target != nil {
			_ = target.Close()
		}
		return result, err
	}, nil
}

type realityTarget struct{ net.Conn }

func portString(port uint16) string { return strconv.Itoa(int(port)) }

// RealityClient composes standard primitives around a connection-owned uTLS
// handshake. Certificate verification parses the supplied DER directly and
// never reads library-private memory with reflection or unsafe pointers.
func RealityClient(ctx context.Context, c net.Conn, settings access.ClientTLS) (net.Conn, error) {
	publicBytes, err := base64.RawURLEncoding.DecodeString(settings.RealityPublicKey)
	if err != nil {
		return nil, errReality
	}
	public, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return nil, errReality
	}
	short, err := hex.DecodeString(settings.RealityShortID)
	if err != nil || len(short) > 8 {
		return nil, errReality
	}
	var authKey []byte
	verified := false
	config := &utls.Config{ServerName: settings.ServerName, MinVersion: utls.VersionTLS13, InsecureSkipVerify: true, SessionTicketsDisabled: true, VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errReality
		}
		cert, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return errReality
		}
		public, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return errReality
		}
		mac := hmac.New(sha512.New, authKey)
		_, _ = mac.Write(public)
		if !hmac.Equal(mac.Sum(nil), cert.Signature) {
			return errReality
		}
		verified = true
		return nil
	}}
	u := utls.UClient(c, config, utls.HelloChrome_Auto)
	if err := u.BuildHandshakeState(); err != nil {
		return nil, err
	}
	// Keep the admitted library's current Chrome TLS1.3 key shares. The pinned
	// REALITY peer requires the hybrid share before optional X25519; filtering it
	// out makes authentication fail. This is TLS key exchange, not VLESSENC.
	hello := u.HandshakeState.Hello
	keys := u.HandshakeState.State13.KeyShareKeys
	if keys == nil || len(hello.Random) != 32 || len(hello.Raw) < 71 {
		return nil, errReality
	}
	ecdhe := keys.Ecdhe
	if ecdhe == nil {
		ecdhe = keys.MlkemEcdhe
	}
	if ecdhe == nil {
		return nil, errReality
	}
	shared, err := ecdhe.ECDH(public)
	if err != nil {
		return nil, errReality
	}
	defer clear(shared)
	authKey = make([]byte, 32)
	defer clear(authKey)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, hello.Random[:20], []byte("REALITY")), authKey); err != nil {
		return nil, err
	}
	hello.SessionId = make([]byte, 32)
	clear(hello.Raw[39:71])
	plain := make([]byte, 16)
	plain[0] = 1
	plain[1] = 8
	plain[2] = 1
	binary.BigEndian.PutUint32(plain[4:], uint32(time.Now().Unix()))
	copy(plain[8:], short)
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, hello.Random[20:], plain, hello.Raw)
	copy(hello.SessionId, sealed)
	copy(hello.Raw[39:71], sealed)
	if err := u.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if !verified {
		return nil, errReality
	}
	return u, nil
}
