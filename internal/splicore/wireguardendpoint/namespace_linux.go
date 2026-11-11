//go:build linux

package wireguardendpoint

import (
	"context"
	"errors"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

type namespaceResult struct {
	err        error
	discardTID int
}

// namespaceRun joins a one-shot locked worker. Only non-main OS threads may
// change namespace: Go's mexit parks m0 rather than destroying it. A worker
// scheduled on m0 holds it safely in the original namespace while a second
// worker runs elsewhere. No process-wide main-thread reservation is needed.
// Callbacks must bound their I/O and leave returned resources owned by the
// caller, including on failure, so cleanup runs after this join in a safe context.
func namespaceRun(ctx context.Context, target int, fn func() error) error {
	result := make(chan namespaceResult, 1)
	go namespaceWorker(ctx, target, fn, result)
	r := <-result
	if r.discardTID != 0 {
		// Sending the result precedes goroutine/thread exit. Do not let the
		// caller start rollback until the poisoned thread actually disappears.
		until := time.Now().Add(3 * time.Second)
		for !errors.Is(unix.Tgkill(os.Getpid(), r.discardTID, 0), unix.ESRCH) {
			if time.Now().After(until) {
				return errors.Join(r.err, &BackendError{Class: CleanupFailure, Operation: "namespace worker disposal"})
			}
			time.Sleep(time.Millisecond)
		}
	}
	return r.err
}

func namespaceWorker(ctx context.Context, target int, fn func() error, result chan<- namespaceResult) {
	runtime.LockOSThread()
	if unix.Gettid() == os.Getpid() {
		next := make(chan namespaceResult, 1)
		go namespaceWorker(ctx, target, fn, next)
		r := <-next
		runtime.UnlockOSThread() // m0 has never changed namespace.
		result <- r
		return
	}
	original, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		runtime.UnlockOSThread() // No namespace change was attempted.
		result <- namespaceResult{err: err}
		return
	}
	var saved unix.Stat_t
	if err = unix.Fstat(original, &saved); err != nil {
		err = errors.Join(err, cleanupError("saved thread namespace close", unix.Close(original)))
		runtime.UnlockOSThread()
		result <- namespaceResult{err: err}
		return
	}
	defer func() {
		if recover() != nil {
			err = &BackendError{Class: RuntimeFailure, Operation: "namespace callback panic"}
		}
		// Entry failure (or rejected unshare) leaves the original namespace
		// intact and does not require privilege to restore it. Also handles
		// callbacks which unshare and then fail before returning a target FD.
		var current unix.Stat_t
		var restore error
		if statErr := unix.Stat("/proc/thread-self/ns/net", &current); statErr != nil || current.Ino != saved.Ino {
			restore = unix.Setns(original, unix.CLONE_NEWNET)
			if restore == nil {
				restore = unix.Stat("/proc/thread-self/ns/net", &current)
				if restore == nil && current.Ino != saved.Ino {
					restore = errors.New("thread namespace identity mismatch")
				}
			}
		}
		r := namespaceResult{err: errors.Join(err, cleanupError("saved thread namespace close", unix.Close(original)))}
		if restore == nil {
			runtime.UnlockOSThread() // Original namespace identity is verified.
		} else {
			r.err = &BackendError{Class: NamespaceRestoreFailure, Operation: "restore thread namespace", Cause: errors.Join(r.err, restore)}
			r.discardTID = unix.Gettid()
			// Never unlock. This is not m0; Go destroys the locked OS thread
			// when this goroutine returns. namespaceRun waits for that exit.
		}
		result <- r
	}()
	if err = ctx.Err(); err != nil {
		return
	}
	if target >= 0 {
		if err = unix.Setns(target, unix.CLONE_NEWNET); err != nil {
			return
		}
	}
	err = fn()
	if err == nil {
		err = ctx.Err()
	}
}

func namespaceInode(fd int) uint64 {
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil {
		return 0
	}
	return stat.Ino
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
	case errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EAFNOSUPPORT), errors.Is(err, unix.EPROTONOSUPPORT):
		class = unavailable
	case errors.Is(err, os.ErrNotExist):
		class = unavailable
	case errors.Is(err, unix.EINVAL) && unavailable == NetNSUnavailable:
		class = NetNSUnavailable
	case errors.Is(err, unix.ENODEV) && unavailable == KernelUnavailable:
		class = KernelUnavailable
	}
	return &BackendError{Class: class, Operation: op, Cause: err}
}
