package application_test

import (
	"context"
	"reflect"
	"testing"
)

func TestPhase20LifecycleEvidenceResourceAssertions(t *testing.T) {
	baseline := phase20Resources{Goroutines: 4, FDs: 12, Listeners: 0, Sessions: 0, UDPWorkers: 0}
	tests := []struct {
		name string
		end  phase20Resources
		want []phase20ResourceFailure
	}{
		{"normal", baseline, nil},
		{"fd-increase", phase20Resources{Goroutines: 4, FDs: 13}, []phase20ResourceFailure{{"fds", 12, 13, 12}}},
		{"fd-decrease", phase20Resources{Goroutines: 4, FDs: 11}, []phase20ResourceFailure{{"fds", 12, 11, 12}}},
		{"session", phase20Resources{Goroutines: 4, FDs: 12, Sessions: 1}, []phase20ResourceFailure{{"sessions", 0, 1, 0}}},
		{"udp-worker", phase20Resources{Goroutines: 4, FDs: 12, UDPWorkers: 1}, []phase20ResourceFailure{{"udp_workers", 0, 1, 0}}},
		{"listener-is-observation-only", phase20Resources{Goroutines: 4, FDs: 12, Listeners: 3}, nil},
		{"multiple", phase20Resources{Goroutines: 4, FDs: 13, Sessions: 2, UDPWorkers: 3}, []phase20ResourceFailure{
			{"fds", 12, 13, 12}, {"sessions", 0, 2, 0}, {"udp_workers", 0, 3, 0},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := phase20StoppedFailures(baseline, test.end); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("stopped failures=%+v want=%+v", got, test.want)
			}
		})
	}
	if got := phase20FinalFailure(baseline, phase20Resources{Goroutines: 6}); !reflect.DeepEqual(got, phase20ResourceFailure{"goroutines", 4, 6, 5}) {
		t.Fatalf("goroutine failure classification=%+v", got)
	}
}

func TestPhase20LifecycleEvidenceIdleResult(t *testing.T) {
	if got := phase20IdleResult(nil); got != "ok" {
		t.Fatalf("nil idle result=%q", got)
	}
	if got := phase20IdleResult(context.DeadlineExceeded); got != "error" {
		t.Fatalf("deadline idle result=%q", got)
	}
}

func TestPhase20LifecycleEvidenceGoroutineCategories(t *testing.T) {
	stack := []byte(`goroutine 1 [running]:
testing.tRunner()

` + `goroutine 2 [select]:
database/sql.(*DB).connectionOpener()

` + `goroutine 3 [IO wait]:
github.com/ike-sh/Splicore/internal/splicore/application_test.phase20Echo.func1()

` + `goroutine 4 [IO wait]:
github.com/ike-sh/Splicore/internal/splicore/application_test.phase20Echo.func1.1()

` + `goroutine 5 [IO wait]:
github.com/ike-sh/Splicore/internal/splicore/clientruntime.(*Manager).accept()

` + `goroutine 6 [select]:
github.com/ike-sh/Splicore/internal/splicore/clientruntime.(*Manager).serveUDP()

` + `goroutine 7 [GC sweep wait]:
runtime.bgsweep()

` + `goroutine 8 [select]:
example.invalid/credential=must-not-appear()
`)
	want := []phase20CategoryCount{
		{"testing", 1}, {"sql", 1}, {"echo_accept", 1}, {"echo_connection", 1},
		{"client_listener", 1}, {"client_udp", 1}, {"runtime_background", 1}, {"unknown", 1},
	}
	if got := phase20GoroutineCategories(stack); !reflect.DeepEqual(got, want) {
		t.Fatalf("categories=%+v want=%+v", got, want)
	}
}

func TestPhase20LifecycleEvidenceFDCategory(t *testing.T) {
	tests := map[string]string{
		"socket:[123]":                      "socket",
		"pipe:[456]":                        "pipe",
		"anon_inode:[eventpoll]":            "anon_inode",
		"/private/config/credential-marker": "file",
		"opaque-resource":                   "unknown",
	}
	for input, want := range tests {
		if got := phase20FDCategory(input); got != want {
			t.Fatalf("category(%q)=%q want=%q", input, got, want)
		}
	}
}
