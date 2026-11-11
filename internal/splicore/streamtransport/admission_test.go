package streamtransport

import (
	"errors"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

func TestSharedAdmissionAbsoluteFallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		c, finish := BeginAdmission(a, 5*time.Second)
		if c != a {
			t.Fatal("ordinary transport unexpectedly wrapped")
		}
		if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
		if err := finish(); err != nil {
			t.Fatal(err)
		}
		go b.Write([]byte{1})
		if _, err := c.Read(make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
	})
}
