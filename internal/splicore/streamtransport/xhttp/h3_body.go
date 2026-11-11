//go:build with_quic

package xhttp

import (
	"io"
	"sync"
)

// The outer request owns the original, non-replayable stream. Sender completion,
// final failure, cancellation and response Close all converge on this one Close.
type h3StreamBody struct {
	io.ReadCloser
	once sync.Once
	err  error
}

func (b *h3StreamBody) Close() error {
	b.once.Do(func() { b.err = b.ReadCloser.Close() })
	return b.err
}

// quic-go closes the attempt body before returning an error, including our retry
// sentinel. Defer that Close until the outer request can classify the result.
// After success, asynchronous sender Close resumes its normal ownership role.
type h3AttemptBody struct {
	*h3StreamBody
	mu                        sync.Mutex
	decided, preserve, closed bool
}

func (b *h3AttemptBody) Close() error {
	b.mu.Lock()
	b.closed = true
	closeBody := b.decided && !b.preserve
	b.mu.Unlock()
	if closeBody {
		return b.h3StreamBody.Close()
	}
	return nil
}

func (b *h3AttemptBody) finish(safeRetry bool) {
	b.mu.Lock()
	b.decided, b.preserve = true, safeRetry
	closeBody := b.closed && !safeRetry
	b.mu.Unlock()
	if closeBody {
		_ = b.h3StreamBody.Close()
	}
}
