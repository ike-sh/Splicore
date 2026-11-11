package clientio

import (
	"context"
	"net"
	"sync"
	"testing"
)

func TestCloseCancelsAndJoinsPendingDialsAndRejectsLateSockets(t *testing.T) {
	o := New()
	ctx, done, err := o.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer b.Close()
	c, err := o.Conn(a)
	if err != nil {
		t.Fatal(err)
	}
	observed := make(chan struct{})
	go func() { <-ctx.Done(); done(); close(observed) }()
	o.Close()
	<-observed
	if _, err = c.Write([]byte("closed")); err == nil {
		t.Fatal("socket remained open")
	}
	a, b = net.Pipe()
	defer b.Close()
	if _, err = o.Conn(a); err == nil {
		t.Fatal("late socket admitted")
	}
	if _, err = a.Write([]byte("late")); err == nil {
		t.Fatal("late socket leaked")
	}
}
func TestConcurrentBeginAndClose(t *testing.T) {
	o := New()
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, done, err := o.Begin(context.Background()); err == nil {
				done()
			}
		}()
	}
	close(start)
	o.Close()
	wg.Wait()
	o.Close()
}
