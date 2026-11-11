//go:build with_quic && with_utls && linux

package native

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	sqHelperEnv    = "SPLICORE_SHADOWQUIC_RESOURCE_HELPER"
	sqResultPrefix = "SHADOWQUIC_RESOURCE_RESULT "
)

var sqHelperModes = map[string]bool{
	"normal": true, "same-process": true, "pipe": true, "pipe-repeat": true,
	"pipe-stair": true, "pipe-slow": true, "convergence-pipe": true,
	"socket": true, "listener": true,
}

type sqFD struct {
	Target string `json:"target"`
	Flags  uint64 `json:"flags"`
}
type sqFDOracle map[int]sqFD

func sqResourceBaseline(t *testing.T) sqFDOracle {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	fds := make(sqFDOracle)
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.ReadFile(filepath.Join("/proc/self/fdinfo", entry.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for line := range strings.SplitSeq(string(info), "\n") {
			if value, ok := strings.CutPrefix(line, "flags:\t"); ok {
				flags, err := strconv.ParseUint(value, 8, 64)
				if err != nil {
					t.Fatal(err)
				}
				fds[fd] = sqFD{Target: target, Flags: flags}
				found = true
				break
			}
		}
		if !found {
			t.Fatal("missing FD flags", entry.Name())
		}
	}
	return fds
}

// Compare resource identity multiplicities, not FD numbers or total counts.
// Neither pipe shape nor a stable count exempts a new application descriptor.
func (baseline sqFDOracle) inspect(current sqFDOracle) error {
	available := make(map[sqFD]int)
	for _, item := range baseline {
		available[item]++
	}
	for fd, item := range current {
		if available[item] == 0 {
			return fmt.Errorf("unexpected lifecycle FD %d: %s flags=%#o", fd, item.Target, item.Flags)
		}
		available[item]--
	}
	return nil
}

// Only the exclusive stdlib calibration may catalogue new pipes. No application
// lifecycle has executed in this process yet, so these are not learned from a
// possibly leaking application. Complete pairs and poll flags are corroboration,
// not an ownership test for pipes observed during subsequent application rounds.
func (baseline sqFDOracle) calibration(current sqFDOracle) error {
	available := make(map[sqFD]int)
	for _, item := range baseline {
		available[item]++
	}
	pipes := make(map[string][]uint64)
	for _, item := range current {
		if available[item] > 0 {
			available[item]--
			continue
		}
		access := item.Flags & syscall.O_ACCMODE
		if !strings.HasPrefix(item.Target, "pipe:[") || !strings.HasSuffix(item.Target, "]") || item.Flags&syscall.O_NONBLOCK == 0 || item.Flags&syscall.O_CLOEXEC == 0 || (access != syscall.O_RDONLY && access != syscall.O_WRONLY) {
			return fmt.Errorf("unexpected stdlib calibration resource: %+v", item)
		}
		pipes[item.Target] = append(pipes[item.Target], access)
	}
	for target, ends := range pipes {
		if len(ends) != 2 || ends[0] == ends[1] {
			return fmt.Errorf("incomplete stdlib pipe %s: %v", target, ends)
		}
	}
	return nil
}

type sqResourceSample struct {
	Phase      string     `json:"phase"`
	Round      int        `json:"round"`
	FDs        sqFDOracle `json:"fds"`
	Goroutines int        `json:"goroutines"`
	NumGC      uint32     `json:"num_gc"`
	Error      string     `json:"error,omitempty"`
}
type sqResourceResult struct {
	Mode    string             `json:"mode"`
	Verdict string             `json:"verdict"`
	Error   string             `json:"error,omitempty"`
	Race    bool               `json:"race"`
	Samples []sqResourceSample `json:"samples"`
}

func sqResourceSubprocess(t *testing.T) bool {
	t.Helper()
	mode := os.Getenv(sqHelperEnv)
	if mode == "" {
		sqRunResourceHelper(t, "normal", false)
		return true
	}
	if !sqHelperModes[mode] {
		t.Fatal("invalid resource helper mode", mode)
	}
	if os.Getenv("GOGC") != "off" || os.Getenv("GOMEMLIMIT") != "off" || runtime.GOMAXPROCS(0) != 1 {
		t.Fatal("resource helper requires GOGC=off GOMEMLIMIT=off GOMAXPROCS=1")
	}
	// Set the same value only to verify the runtime accepted GOGC=off. This is
	// confined to the child; no package test shares this process or GC state.
	previous := debug.SetGCPercent(-1)
	if previous != -1 {
		t.Fatal("automatic GC was not disabled at process startup", previous)
	}
	if debug.SetMemoryLimit(-1) != int64(^uint64(0)>>1) {
		t.Fatal("memory-limit GC remains enabled")
	}
	return false
}

func sqRunResourceHelper(t *testing.T, mode string, wantLeak bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestShadowQUICNativeMultiUserLifecycleAndBounds$", "-test.count=1", "-test.v", "-test.timeout=50s")
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		switch key {
		case sqHelperEnv, "GOGC", "GOMEMLIMIT", "GOMAXPROCS", "GODEBUG":
			continue
		}
		cmd.Env = append(cmd.Env, item)
	}
	cmd.Env = append(cmd.Env, sqHelperEnv+"="+mode, "GOGC=off", "GOMEMLIMIT=off", "GOMAXPROCS=1")
	output, err := cmd.CombinedOutput()
	t.Logf("helper %s output:\n%s", mode, output)
	var result *sqResourceResult
	for line := range strings.SplitSeq(string(output), "\n") {
		if body, ok := strings.CutPrefix(line, sqResultPrefix); ok {
			var r sqResourceResult
			if e := json.Unmarshal([]byte(body), &r); e != nil {
				t.Fatal(e)
			}
			if result != nil {
				t.Fatal("duplicate helper result")
			}
			result = &r
		}
	}
	if ctx.Err() != nil || result == nil {
		t.Fatalf("resource helper did not complete: %v: %v", err, ctx.Err())
	}
	if result.Mode != mode {
		t.Fatal("helper mode mismatch", result.Mode)
	}
	if wantLeak {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 || result.Verdict != "FAIL" || !strings.Contains(result.Error, "unexpected lifecycle FD") {
			t.Fatalf("expected resource leak rejection: %+v: %v", result, err)
		}
		target := "pipe:["
		if mode == "socket" || mode == "listener" {
			target = "socket:["
		}
		if !strings.Contains(result.Error, target) {
			t.Fatal("wrong resource rejected", result.Error)
		}
	} else if err != nil || result.Verdict != "PASS" {
		t.Fatalf("resource helper failed: %+v: %v", result, err)
	}
}

// The echo fixture is test-owned and joins each completed connection. Race builds
// use the same TCP/FIN/payload workload with buffered fixture I/O: sync.Pool.Put
// deliberately drops 1/4 of objects under -race, and with GC off those discarded
// stdlib pipes cannot be reclaimed. Production protocol/relay code stays raced.
func sqLifecycleTCP(t *testing.T) (net.Listener, func()) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{}, 1)
	var mu sync.Mutex
	active := make(map[net.Conn]bool)
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			active[c] = true
			mu.Unlock()
			wg.Go(func() {
				if sqResourceRace {
					_, _ = io.Copy(struct{ io.Writer }{c}, struct{ io.Reader }{c})
				} else {
					_, _ = io.Copy(c, c)
				}
				c.Close()
				mu.Lock()
				delete(active, c)
				mu.Unlock()
				done <- struct{}{}
			})
		}
	})
	t.Cleanup(func() {
		l.Close()
		mu.Lock()
		for c := range active {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return l, func() {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("TCP fixture copy did not finish")
		}
	}
}

// No GC (explicit or automatic) is permitted from child startup through the
// verdict. The process exits after the verdict, including intentional leaks.
func sqResourceLifecycles(t *testing.T, target net.Addr, waitTCP func(), cycle func()) {
	t.Helper()
	mode := os.Getenv(sqHelperEnv)
	result := sqResourceResult{Mode: mode, Verdict: "PASS", Race: sqResourceRace}
	var initial runtime.MemStats
	runtime.ReadMemStats(&initial)
	if initial.NumGC != 0 {
		t.Fatal("GC occurred before resource measurement", initial.NumGC)
	}
	beforeG := runtime.NumGoroutine()
	sample := func(phase string, round int, baseline sqFDOracle) sqFDOracle {
		current := sqResourceBaseline(t)
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		s := sqResourceSample{Phase: phase, Round: round, FDs: current, Goroutines: runtime.NumGoroutine(), NumGC: ms.NumGC}
		if ms.NumGC != initial.NumGC {
			t.Fatal("GC occurred during leak verdict window")
		}
		if baseline != nil {
			if err := baseline.inspect(current); err != nil {
				s.Error = err.Error()
				result.Verdict = "FAIL"
				if result.Error == "" {
					result.Error = s.Error
				}
			}
		}
		result.Samples = append(result.Samples, s)
		return current
	}
	emit := func() {
		b, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("%s%s\n", sqResultPrefix, b)
	}
	boot := sample("startup", 0, nil)
	// Three equal samples (two stable transitions) with at most four pure-stdlib
	// copy rounds. P=1 and no GC exclude P migration and cache eviction. No FD
	// count allowance is used; all extra identities must come from this window.
	prior := boot
	stable := 0
	var catalogue sqFDOracle
	for round := 1; round <= 4; round++ {
		c, err := net.DialTimeout("tcp4", target.String(), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if err = sqExchange(c, 65536, true); err != nil {
			t.Fatal(err)
		}
		waitTCP()
		current := sample("stdlib-calibration", round, nil)
		if err := boot.calibration(current); err != nil {
			t.Fatal(err)
		}
		if prior.inspect(current) == nil && current.inspect(prior) == nil {
			stable++
		} else {
			stable = 0
		}
		prior = current
		if stable == 2 {
			catalogue = current
			break
		}
	}
	if catalogue == nil {
		t.Fatal("stdlib splice cache did not converge within four rounds")
	}
	// Genuine application convergence never learns unknown descriptors, even on
	// its FIRST cycle. Only the exclusive stdlib catalogue may contain new pipes.
	for round := 1; round <= 3; round++ {
		cycle()
		if mode == "convergence-pipe" && round == 1 {
			sqForgetPipes(t, 1)
		}
		sample("lifecycle-convergence", round, catalogue)
		if result.Verdict == "FAIL" {
			emit()
			t.Fatal(result.Error)
		}
	}
	// The measured baseline is established by genuine nonleaking lifecycles.
	// It cannot contain more identities than the pre-application catalogue.
	measured := result.Samples[len(result.Samples)-1].FDs
	rounds := 3
	if mode == "same-process" {
		rounds = 20
	}
	if mode == "pipe-stair" {
		rounds = 6
	}
	if mode == "pipe-slow" {
		rounds = 7
	}
	for round := 1; round <= rounds; round++ {
		cycle()
		switch mode {
		case "pipe":
			if round == 1 {
				sqForgetPipes(t, 3)
			}
		case "pipe-repeat":
			sqForgetPipes(t, 1)
		case "pipe-stair":
			if round%2 == 1 {
				sqForgetPipes(t, 1)
			}
		case "pipe-slow":
			if round == 3 || round == 6 {
				sqForgetPipes(t, 1)
			}
		case "socket":
			if round == 1 {
				sqForgetSocket(t, false)
			}
		case "listener":
			if round == 1 {
				sqForgetSocket(t, true)
			}
		}
		sample("measured-lifecycle", round, measured)
		// Negative controls retain every rejected sample to prove continued or
		// stair-step growth, without ever updating the baseline or retrying a test.
		if (mode == "normal" || mode == "same-process") && result.Verdict == "FAIL" {
			emit()
			t.Fatal(result.Error)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > beforeG+8 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if runtime.NumGoroutine() > beforeG+8 {
		result.Verdict = "FAIL"
		result.Error = "goroutine growth"
	}
	sample("verdict", 0, measured)
	emit()
	if result.Verdict != "PASS" {
		t.Fatal(result.Error)
	}
}

//go:noinline
func sqForgetPipes(t *testing.T, pairs int) {
	t.Helper()
	for range pairs {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		// Intentionally no Close and no surviving application references.
		runtime.KeepAlive(r)
		runtime.KeepAlive(w)
	}
}

//go:noinline
func sqForgetSocket(t *testing.T, listener bool) {
	t.Helper()
	if listener {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		duplicate, err := net.Listen("tcp4", l.Addr().String())
		if err == nil {
			duplicate.Close()
			t.Fatal("retained listener allowed rebind")
		}
		runtime.KeepAlive(l)
	} else {
		p, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		runtime.KeepAlive(p)
	}
}

func TestShadowQUICResourceOracleRetainedSocket(t *testing.T) { sqRunResourceHelper(t, "socket", true) }

func TestShadowQUICResourceOracleRetainedListener(t *testing.T) {
	sqRunResourceHelper(t, "listener", true)
}

func TestShadowQUICResourceOracleAccumulatingPipes(t *testing.T) {
	sqRunResourceHelper(t, "pipe-repeat", true)
}

func TestShadowQUICResourceOracleOrdinaryPipeWithoutClose(t *testing.T) {
	sqRunResourceHelper(t, "pipe", true)
}

func TestShadowQUICResourceOracleStairStep(t *testing.T) { sqRunResourceHelper(t, "pipe-stair", true) }

func TestShadowQUICResourceOracleSlowGrowth(t *testing.T) { sqRunResourceHelper(t, "pipe-slow", true) }

func TestShadowQUICResourceOracleConvergenceCannotLearnPipe(t *testing.T) {
	sqRunResourceHelper(t, "convergence-pipe", true)
}

func TestShadowQUICResourceOracleSameProcess(t *testing.T) {
	sqRunResourceHelper(t, "same-process", false)
}

func TestShadowQUICResourceOracleGrowthAndCache(t *testing.T) {
	baseline := sqFDOracle{0: {Target: "/dev/null"}}
	for _, counts := range [][]int{{0, 1, 2, 3}, {0, 1, 1, 2, 2, 3}, {0, 0, 1, 1, 1, 2, 2}} {
		for _, pairs := range counts {
			current := sqFDOracle{9: baseline[0]}
			for i := range pairs {
				current[20+i*2] = sqFD{Target: fmt.Sprintf("pipe:[%d]", i), Flags: syscall.O_NONBLOCK | syscall.O_CLOEXEC}
				current[21+i*2] = sqFD{Target: fmt.Sprintf("pipe:[%d]", i), Flags: syscall.O_NONBLOCK | syscall.O_CLOEXEC | syscall.O_WRONLY}
			}
			if (baseline.inspect(current) != nil) != (pairs > 0) {
				t.Fatal("growth incorrectly classified", counts, pairs)
			}
		}
	}
	for _, target := range []string{"socket:[123]", "anon_inode:[eventfd]", "/tmp/leaked-file", "pipe:[123]"} {
		if baseline.inspect(sqFDOracle{0: baseline[0], 10: {Target: target}}) == nil {
			t.Fatal("unknown resource accepted", target)
		}
	}
	// Identity relocation is harmless; duplicate descriptors are not.
	if baseline.inspect(sqFDOracle{15: baseline[0]}) != nil {
		t.Fatal("FD number treated as identity")
	}
	if baseline.inspect(sqFDOracle{0: baseline[0], 15: baseline[0]}) == nil {
		t.Fatal("duplicate resource accepted")
	}
}
