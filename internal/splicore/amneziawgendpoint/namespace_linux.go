//go:build linux

package amneziawgendpoint

import (
	"context"
	"errors"
	"os"

	WG "github.com/ike-sh/Splicore/internal/splicore/wireguardendpoint"
	"golang.org/x/sys/unix"
)

// Both native protocols use the same audited namespace executor. Translate
// every branch so fatal restore/cleanup failures retain their precedence.
func namespaceRun(ctx context.Context, target int, fn func() error) error {
	return translateNamespaceError(WG.RunInNamespace(ctx, target, fn))
}

func translateNamespaceError(err error) error {
	if err == nil {
		return nil
	}
	if e, ok := err.(*WG.BackendError); ok {
		return &BackendError{Class: Availability(e.Class), Operation: e.Operation, Cause: translateNamespaceError(e.Cause)}
	}
	switch e := err.(type) {
	case interface{ Unwrap() []error }:
		causes := e.Unwrap()
		result := make([]error, len(causes))
		for i, c := range causes {
			result[i] = translateNamespaceError(c)
		}
		return errors.Join(result...)
	}
	return err
}

func namespaceInode(fd int) uint64 {
	var s unix.Stat_t
	if unix.Fstat(fd, &s) != nil {
		return 0
	}
	return s.Ino
}

func kernelError(op string, unavailable Availability, err error) error {
	if err == nil {
		return nil
	}
	if backendAvailability(err) == NamespaceRestoreFailure {
		return &BackendError{Class: NamespaceRestoreFailure, Operation: op, Cause: err}
	}
	if _, ok := errors.AsType[*BackendError](err); ok {
		return err
	}
	class := RuntimeFailure
	switch {
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		class = InsufficientPrivilege
	case errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EAFNOSUPPORT), errors.Is(err, unix.EPROTONOSUPPORT), errors.Is(err, os.ErrNotExist):
		class = unavailable
	case errors.Is(err, unix.EINVAL) && unavailable == NetNSUnavailable:
		class = NetNSUnavailable
	case errors.Is(err, unix.ENODEV) && unavailable == KernelUnavailable:
		class = KernelUnavailable
	}
	return &BackendError{Class: class, Operation: op, Cause: err}
}
