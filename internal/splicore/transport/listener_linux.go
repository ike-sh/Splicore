package transport

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"

	"golang.org/x/sys/unix"
)

type (
	principalKey struct{}
	Principal    struct {
		UID uint32
		GID uint32
		PID int32
	}
)

func Peer(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

type peerConn struct {
	net.Conn
	principal Principal
}
type localListener struct{ *net.UnixListener }

func Listen(path string) (net.Listener, error) {
	if err := CheckControlPath(path); err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, identity.Err(identity.Unavailable, "cannot create control directory")
	}
	if err := CheckControlPath(path); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return nil, identity.Err(identity.Unavailable, "control socket already exists; operator review required")
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, identity.Err(identity.Unavailable, "cannot bind control socket")
	}
	if err = os.Chmod(path, 0o660); err != nil {
		l.Close()
		return nil, identity.Err(identity.Unavailable, "cannot protect control socket")
	}
	return &localListener{l}, nil
}

func (l *localListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		raw, err := conn.SyscallConn()
		if err != nil {
			conn.Close()
			continue
		}
		var cred *unix.Ucred
		var peerErr error
		if err = raw.Control(func(fd uintptr) { cred, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil || peerErr != nil || cred == nil || (cred.Uid != uint32(os.Geteuid()) && cred.Uid != 0) {
			conn.Close()
			continue
		}
		return &peerConn{conn, Principal{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}}, nil
	}
}

func ConnContext(ctx context.Context, conn net.Conn) context.Context {
	if c, ok := conn.(*peerConn); ok {
		return context.WithValue(ctx, principalKey{}, c.principal)
	}
	return ctx
}
func ProductionSupported() bool { return true }

// CheckControlPath checks path/permissions without creating or binding anything.
func CheckControlPath(path string) error {
	if !filepath.IsAbs(path) || len(path) >= len(unix.RawSockaddrUnix{}.Path) {
		return identity.Err(identity.Invalid, "control socket path must be absolute and fit the Unix socket limit")
	}
	dir := filepath.Dir(path)
	existing := dir
	for {
		_, err := os.Lstat(existing)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) {
			return identity.Err(identity.Unavailable, "cannot inspect control directory")
		}
		existing = filepath.Dir(existing)
	}
	resolved, err := filepath.EvalSymlinks(existing)
	if err != nil || resolved != filepath.Clean(existing) {
		return identity.Err(identity.Invalid, "unsafe control directory path")
	}
	if existing != dir {
		return nil
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return identity.Err(identity.Invalid, "control directory must have mode 0700")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return identity.Err(identity.Invalid, "control directory owner mismatch")
	}
	return nil
}
