package wire

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

func TestReviewFix1RequestClockReplay(t *testing.T) {
	key := oracleKey()
	r, err := NewRequest(access.Endpoint{Host: "localhost", Port: 443}, TCP, None, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := EncodeRequest(key, r, time.Unix(1000, 0), nil)
	if err != nil {
		t.Fatal(err)
	}
	bank := NewReplay(65536)
	users := []User{NewUser("synthetic", key)}
	var now atomic.Int64
	now.Store(1000)
	clock := func() time.Time { return time.Unix(now.Load(), 0) }
	var wg sync.WaitGroup
	var wins atomic.Int64
	start := make(chan struct{})
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, _, err := ReadRequestWithClock(bytes.NewReader(b), users, bank, clock); err == nil {
				wins.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("duplicate admissions", wins.Load())
	}
	if _, _, err := ReadRequestWithClock(bytes.NewReader(b), users, bank, clock); err == nil {
		t.Fatal("sequential replay")
	}
	entries, _, _ := bank.Snapshot(1000)
	if entries != 3 {
		t.Fatal("token accounting", entries)
	}
	now.Store(1120)
	if n, _, _ := bank.Snapshot(1120); n != 3 {
		t.Fatal("inclusive TTL")
	}
	now.Store(1121)
	if n, _, _ := bank.Snapshot(1121); n != 0 {
		t.Fatal("TTL cleanup")
	}
	now.Store(1000)
	if _, _, err := ReadRequestWithClock(bytes.NewReader(b), users, bank, clock); err == nil {
		t.Fatal("rollback replay resurrected")
	}
	t.Log(fmt.Sprintf("valid_accepted=%d concurrent_duplicates_rejected=63 sequential_replay_rejected=1 rollback_rejected=1 unexpected_accepts=0", wins.Load()))
}
