package native

import (
	"context"
	"sync"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/engine/traffic"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
)

func TestPhase15StoppedHandleRejectsStaleActivation(t *testing.T) {
	done := make(chan struct{})
	close(done)
	snell := &Handle{closed: true, done: done}
	vless := &vlessHandle{closed: true, done: done, total: &traffic.Counter{}}
	hy2 := &hysteria2Handle{closed: true, total: &traffic.Counter{}}
	tuic := &tuicHandle{closed: true, total: &traffic.Counter{}}
	for _, tc := range []struct {
		name     string
		handle   ports.RuntimeHandle
		admitted func() bool
	}{
		{"snell", snell, snell.admitted.Load}, {"vless", vless, vless.admitted.Load},
		{"hysteria2", hy2, hy2.admitted.Load}, {"tuic", tuic, tuic.admitted.Load},
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
