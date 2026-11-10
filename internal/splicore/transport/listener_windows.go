package transport

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/Microsoft/go-winio"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/privatefs"
	"golang.org/x/sys/windows"
)

// The existing bootstrap field is a stable local identity on Windows. It is not
// opened as a socket file, so Windows pipe names do not inherit AF_UNIX limits.
func controlPipe(path string) (string, error) {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
		return "", identity.Err(identity.Invalid, "bootstrap paths must be absolute")
	}
	sid, err := privatefs.UserSID()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(sid.String() + "\x00" + strings.ToLower(filepath.Clean(path))))
	return fmt.Sprintf(`\\.\pipe\splicore-%x`, digest[:]), nil
}

func Listen(path string) (net.Listener, error) {
	name, err := controlPipe(path)
	if err != nil {
		return nil, err
	}
	sddl, err := privatefs.Descriptor(false)
	if err != nil {
		return nil, err
	}
	// go-winio rejects remote clients and exclusively creates the first pipe
	// instance. DACL authorization is performed by the OS before HTTP admission.
	l, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: sddl, InputBufferSize: 65536, OutputBufferSize: 65536})
	if err != nil {
		return nil, identity.Err(identity.Unavailable, "cannot bind private control pipe")
	}
	return l, nil
}

func dialControl(ctx context.Context, path string) (net.Conn, error) {
	name, err := controlPipe(path)
	if err != nil {
		return nil, err
	}
	c, err := winio.DialPipeAccess(ctx, name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL)
	if err != nil {
		return nil, err
	}
	// Authenticate the actual connected object, not a separately opened path.
	// This rejects a foreign-user server squatting on the predictable pipe name.
	file, ok := c.(interface{ Fd() uintptr })
	if !ok {
		c.Close()
		return nil, identity.Err(identity.Unavailable, "production control transport unavailable")
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err == nil {
		err = privatefs.CheckDescriptor(sd)
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func ConnContext(ctx context.Context, _ net.Conn) context.Context { return ctx }
func ProductionSupported() bool                                   { return true }

func CheckControlPath(path string) error { _, err := controlPipe(path); return err }
