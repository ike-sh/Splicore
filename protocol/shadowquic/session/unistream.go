//go:build with_quic

package session

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"time"

	quic "github.com/metacubex/jls-quic-go"
)

// The control association owns mappings; a unistream owns exactly one CID.
// Both peers can send payload streams after the client opens CMD4.
func (c *connection) unistreams() {
	defer c.wg.Done()
	for {
		st, err := c.conn.AcceptUniStream(c.conn.Context())
		if err != nil {
			return
		}
		c.mu.Lock()
		if c.closing || len(c.uni) >= c.limits.MaxFlows {
			c.mu.Unlock()
			st.CancelRead(0)
			continue
		}
		c.uni[st] = nil
		c.wg.Add(1)
		c.mu.Unlock()
		go c.readUnistream(st)
	}
}

func (c *connection) readUnistream(st *quic.ReceiveStream) {
	defer c.wg.Done()
	defer st.CancelRead(0)
	defer func() {
		c.mu.Lock()
		delete(c.uni, st)
		for id, active := range c.uniIDs {
			if active == st {
				delete(c.uniIDs, id)
			}
		}
		c.mu.Unlock()
	}()
	deadline := time.Now().Add(c.limits.Handshake())
	_ = st.SetReadDeadline(deadline)
	var head [2]byte
	if _, err := io.ReadFull(st, head[:]); err != nil {
		return
	}
	id := binary.BigEndian.Uint16(head[:])
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	var target destination
	for {
		c.mu.Lock()
		found, ok := c.receive[id]
		if c.closing || c.uniIDs[id] != nil || !ok && c.seen[id/64]&(uint64(1)<<(id%64)) != 0 {
			c.mu.Unlock()
			return
		}
		if ok {
			if !found.packet.overStream {
				c.mu.Unlock()
				return
			}
			target = found
			c.uni[st], c.uniIDs[id] = found.packet, st
			c.mu.Unlock()
			break
		}
		changed := c.changed
		c.mu.Unlock()
		select {
		case <-changed:
		case <-timer.C:
			return
		case <-c.conn.Context().Done():
			return
		}
	}
	_ = st.SetReadDeadline(time.Time{})
	for {
		payload, err := readStreamPayload(st)
		if err != nil {
			return
		}
		c.deliver(target.packet, datagram{data: payload, dst: target.endpoint, id: id})
	}
}

func (p *packet) openSendStream() (*quic.SendStream, error) {
	ctx, cancel := context.WithCancel(p.ctx)
	done, joined := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		for {
			deadline, changed := p.deadline(true)
			timer, expired := deadlineTimer(deadline)
			select {
			case <-done:
				if timer != nil {
					timer.Stop()
				}
				return
			case <-p.closed:
				if timer != nil {
					timer.Stop()
				}
				cancel()
				return
			case <-expired:
				cancel()
				return
			case <-changed:
				if timer != nil {
					timer.Stop()
				}
			}
		}
	}()
	st, err := p.conn.conn.OpenUniStreamSync(ctx)
	close(done)
	<-joined
	cancel()
	if err != nil {
		select {
		case <-p.closed:
			return nil, net.ErrClosed
		default:
		}
		deadline, _ := p.deadline(true)
		if !deadline.IsZero() && !deadline.After(time.Now()) {
			return nil, os.ErrDeadlineExceeded
		}
	}
	return st, err
}

func (p *packet) writeStream(id uint16, b []byte) (int, error) {
	p.mu.Lock()
	st := p.sendStreams[id]
	p.mu.Unlock()
	newStream := st == nil
	if newStream {
		var err error
		st, err = p.openSendStream()
		if err != nil {
			return 0, err
		}
		p.mu.Lock()
		select {
		case <-p.closed:
			p.mu.Unlock()
			st.CancelWrite(0)
			return 0, net.ErrClosed
		default:
		}
		_ = st.SetWriteDeadline(p.writeDeadline)
		p.sendStreams[id] = st
		p.mu.Unlock()
	}
	frame := make([]byte, 0, len(b)+4)
	if newStream {
		frame = binary.BigEndian.AppendUint16(frame, id)
	}
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(b)))
	frame = append(frame, b...)
	n, err := st.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	if err != nil {
		// A partial length/payload cannot be replayed on this association.
		_ = p.Close()
		return 0, err
	}
	p.touch()
	return len(b), nil
}
