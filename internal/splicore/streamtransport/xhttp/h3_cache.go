//go:build with_quic

package xhttp

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
)

// Each managed Transport may create exactly one physical connection. A second
// Dial is requested only after quic-go has decided that the request can safely
// be retried. Hand that decision back to the origin cache instead of allowing
// a detached physical connection to disappear inside the library's cache.
var errH3CarrierRetry = errors.New("XHTTP HTTP/3 carrier retry")

type h3Carrier struct {
	owner     *h3Transport
	transport *http3.Transport
	dialed    atomic.Bool
	// Protected by owner.mu. Cache retention and request/body leases are distinct.
	refs     int
	retiring bool
	socket   *h3Socket
	once     sync.Once
}

// GotConn's net.Conn exposes addresses but no stable QUIC identity. Bind the
// request to its leased carrier directly: a retired socket can release its UDP
// endpoint before registry cleanup, and a new carrier can immediately reuse it.
func (c *h3Carrier) connectionContext() context.Context {
	c.owner.mu.Lock()
	defer c.owner.mu.Unlock()
	if c.socket == nil || c.socket.conn == nil {
		return nil
	}
	return c.socket.conn.Context()
}

func (c *h3Carrier) close() {
	c.once.Do(func() {
		_ = c.transport.Close()
		c.owner.mu.Lock()
		s := c.socket
		var q *quic.Conn
		if s != nil {
			q = s.conn
		}
		c.owner.mu.Unlock()
		if s != nil {
			if q != nil {
				_ = q.CloseWithError(0, "unused HTTP/3 carrier")
			}
			s.close()
		}
		c.owner.mu.Lock()
		delete(c.owner.sockets, s)
		delete(c.owner.carriers, c)
		c.owner.mu.Unlock()
	})
}

// The caller holds h.mu. The cache slot is chosen before dialing, never by
// completion order. Only one reusable carrier is retained for this origin.
func (h *h3Transport) newCarrier() *h3Carrier {
	c := &h3Carrier{owner: h}
	c.transport = &http3.Transport{
		TLSClientConfig: h.TLSClientConfig, QUICConfig: h.QUICConfig,
		MaxResponseHeaderBytes: h.MaxResponseHeaderBytes, DisableCompression: h.DisableCompression,
		Dial: func(ctx context.Context, address string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			if !c.dialed.CompareAndSwap(false, true) {
				return nil, errH3CarrierRetry
			}
			return h.dialOwned(ctx, address, tc, qc, c)
		},
	}
	h.carriers[c] = true
	return c
}

func (h *h3Transport) acquireCarrier(previous *h3Carrier, replace bool) (*h3Carrier, error) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, net.ErrClosed
	}
	old := h.cached
	if old == nil || replace || old == previous {
		h.cached = h.newCarrier()
	}
	c := h.cached
	c.refs++
	var retire *h3Carrier
	if old != nil && old != c && old.refs == 0 && !old.retiring {
		old.retiring = true
		retire = old
	}
	h.mu.Unlock()
	if retire != nil {
		retire.close()
	}
	return c, nil
}

func (h *h3Transport) releaseCarrier(c *h3Carrier) {
	h.mu.Lock()
	c.refs--
	retire := c.refs == 0 && h.cached != c && !c.retiring
	if retire {
		c.retiring = true
	}
	h.mu.Unlock()
	if retire {
		c.close()
	}
}

func (h *h3Transport) failedCarrier(c *h3Carrier) {
	h.mu.Lock()
	if h.cached == c {
		h.cached = nil
	}
	h.mu.Unlock()
}

type h3CarrierBody struct {
	io.ReadCloser
	carrier      *h3Carrier
	closeRequest func()
	once         sync.Once
}

func (b *h3CarrierBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() {
		if b.closeRequest != nil {
			b.closeRequest()
		}
		b.carrier.owner.releaseCarrier(b.carrier)
	})
	return err
}

type h3RetryRequest struct {
	mu       sync.Mutex
	attempts int
	replay   io.ReadCloser
}

func (s *h3RetryRequest) count() int { s.mu.Lock(); defer s.mu.Unlock(); return s.attempts }
func (s *h3RetryRequest) takeReplay() io.ReadCloser {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.replay
	s.replay = nil
	return b
}

func (h *h3Transport) roundTrip(r *http.Request, watch *h3RequestWatch) (*http.Response, error) {
	var stream *h3StreamBody
	var closeRequest func()
	if r.Body != nil && r.Body != http.NoBody && r.GetBody == nil {
		stream = &h3StreamBody{ReadCloser: r.Body}
		stop := context.AfterFunc(r.Context(), func() { _ = stream.Close() })
		closeRequest = func() { stop(); _ = stream.Close() }
	}
	handedOff := false
	defer func() {
		if !handedOff && closeRequest != nil {
			closeRequest()
		}
	}()
	state := &h3RetryRequest{}
	if getBody := r.GetBody; getBody != nil {
		r.GetBody = func() (io.ReadCloser, error) {
			body, err := getBody()
			if err == nil {
				state.mu.Lock()
				state.replay = body
				state.mu.Unlock()
			}
			return body, err
		}
	}
	defer func() {
		if body := state.takeReplay(); body != nil {
			_ = body.Close()
		}
	}()
	var previous *h3Carrier
	replace := false
	for {
		if err := r.Context().Err(); err != nil {
			return nil, err
		}
		c, err := h.acquireCarrier(previous, replace)
		if err != nil {
			return nil, err
		}
		before := state.count()
		trace := &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) {
			state.mu.Lock()
			state.attempts++
			state.mu.Unlock()
			if watch != nil {
				watch.selectAttempt(c.connectionContext())
			}
		}}
		attempt := r.WithContext(httptrace.WithClientTrace(r.Context(), trace))
		var body *h3AttemptBody
		if stream != nil {
			body = &h3AttemptBody{h3StreamBody: stream}
			attempt.Body = body
		}
		resp, err := c.transport.RoundTrip(attempt)
		if body != nil {
			// With no GetBody, quic-go reaches this sentinel only when opening
			// the request stream failed before sending. Partially sent streams
			// remain non-replayable; no generic error preserves their body.
			body.finish(errors.Is(err, errH3CarrierRetry) && r.Context().Err() == nil && state.count() < 2)
		}
		if err == nil {
			resp.Body = &h3CarrierBody{ReadCloser: resp.Body, carrier: c, closeRequest: closeRequest}
			handedOff = true
			return resp, nil
		}
		// Actual failure invalidates only this generation, never whichever healthy
		// generation another request has already placed in the cache slot.
		// quic-go leaves the cache intact when only this request is canceled.
		// In particular a canceled packet upload must not evict the healthy
		// carrier retained for the session's download or for later requests.
		if r.Context().Err() == nil {
			h.failedCarrier(c)
		}
		h.releaseCarrier(c)
		if !errors.Is(err, errH3CarrierRetry) {
			return nil, err
		}
		// Across the per-carrier Transports retain quic-go's one retry per request.
		// In particular, do not replay a third request after two physical attempts.
		if state.count() >= 2 {
			return nil, errH3CarrierRetry
		}
		if body := state.takeReplay(); body != nil {
			copy := *r
			copy.Body = body
			r = &copy
		}
		previous, replace = c, state.count() > before
	}
}
