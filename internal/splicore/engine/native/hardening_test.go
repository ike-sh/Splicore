package native

import (
	"context"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/internal/splicore/ports"
)

func TestPhase15StoppedHandleRejectsStaleActivation(t *testing.T) {
	done := make(chan struct{})
	close(done)
	snell := &Handle{closed: true, done: done}
	vless := &vlessHandle{closed: true, done: done, total: &meter{}}
	quic := &quicHandle{closed: true, total: &meter{}}
	mieru := &mieruHandle{closed: true, done: done, total: &meter{}}
	for _, tc := range []struct {
		name     string
		handle   ports.RuntimeHandle
		admitted func() bool
	}{
		{"snell", snell, snell.admitted.Load}, {"vless", vless, vless.admitted.Load},
		{"quic", quic, quic.admitted.Load}, {"mieru", mieru, mieru.admitted.Load},
	} {
		t.Run(tc.name, func(t *testing.T) {
			barrier := make(chan struct{})
			var workers sync.WaitGroup
			for i := 0; i < 16; i++ {
				workers.Add(1)
				go func() {
					defer workers.Done()
					<-barrier
					tc.handle.Activate()
					if err := tc.handle.Start(context.Background()); err == nil {
						t.Error("closed handle restarted")
					}
					if err := tc.handle.Close(context.Background()); err != nil {
						t.Error(err)
					}
				}()
			}
			close(barrier)
			workers.Wait()
			if tc.admitted() {
				t.Error("stale callback reopened admission")
			}
		})
	}
}
