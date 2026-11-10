package hysteria

import (
	"errors"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
)

// ERROR_PRIVILEGE_NOT_HELD is Win32 error 1314. Other failures, and all CI
// failures, must fail rather than hide an unverified security boundary.
func allowUnavailableSymlinkFixture(goos, ci, githubActions string, err error) bool {
	return goos == "windows" && ci == "" && githubActions == "" && errors.Is(err, syscall.Errno(1314))
}

func createBoundarySymlink(t *testing.T, target, link string) {
	t.Helper()
	t.Cleanup(func() {
		if err := os.Remove(link); err != nil {
			if !os.IsNotExist(err) {
				t.Error("remove fixture symlink:", err)
			}
			return
		}
		t.Log("real file symlink cleanup completed")
	})
	err := os.Symlink(target, link)
	if err != nil {
		var code syscall.Errno
		if errors.As(err, &code) {
			t.Logf("os.Symlink failed: GOOS=%s errno=%d CI=%t GITHUB_ACTIONS=%t", runtime.GOOS, code, os.Getenv("CI") != "", os.Getenv("GITHUB_ACTIONS") != "")
		}
		if allowUnavailableSymlinkFixture(runtime.GOOS, os.Getenv("CI"), os.Getenv("GITHUB_ACTIONS"), err) {
			t.Skipf("NOT_EXECUTED_ENVIRONMENT: Windows file symlink requires privilege (Win32 1314): %v", err)
		}
		t.Fatal("create real file symlink (required in CI):", err)
	}
	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("fixture is not a real symlink:", err)
	}
	got, err := os.Readlink(link)
	if err != nil || filepath.Clean(got) != filepath.Clean(target) {
		t.Fatal("fixture symlink target:", got, err)
	}
	t.Logf("real file symlink created: %s -> %s", link, target)
}

func TestMasqueradeSymlinkEnvironmentPolicy(t *testing.T) {
	permission := &os.LinkError{Op: "symlink", Err: syscall.Errno(1314)}
	for _, tc := range []struct {
		name, goos, ci, githubActions string
		err                           error
		allow                         bool
	}{
		{"local-windows-1314", "windows", "", "", permission, true},
		{"ci-1314", "windows", "true", "", permission, false},
		{"github-actions-1314", "windows", "", "true", permission, false},
		{"ci-marker-present", "windows", "false", "", permission, false},
		{"linux-1314", "linux", "", "", permission, false},
		{"access-denied-5", "windows", "", "", &os.LinkError{Err: syscall.Errno(5)}, false},
		{"missing-file-2", "windows", "", "", &os.LinkError{Err: syscall.Errno(2)}, false},
		{"missing-path-3", "windows", "", "", &os.LinkError{Err: syscall.Errno(3)}, false},
		{"unsupported-filesystem-50", "windows", "", "", &os.LinkError{Err: syscall.Errno(50)}, false},
		{"untyped-message", "windows", "", "", errors.New("Win32 1314 Access Denied"), false},
		{"success", "windows", "", "", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := allowUnavailableSymlinkFixture(tc.goos, tc.ci, tc.githubActions, tc.err); got != tc.allow {
				t.Fatalf("allow unavailable fixture = %t, want %t", got, tc.allow)
			}
		})
	}
}

func TestRootFileTraversalAndHTTPHTTPSProxyBoundaries(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		root := t.TempDir()
		outside := t.TempDir()
		target := filepath.Join(outside, "secret")
		if err := os.WriteFile(target, []byte("outside-secret"), 0600); err != nil {
			t.Fatal("create outside target:", err)
		}
		if err := os.WriteFile(filepath.Join(root, "visible"), []byte("visible"), 0600); err != nil {
			t.Fatal("fixture parent is not writable:", err)
		}
		t.Log("fixture parent write and outside target creation succeeded")
		checkBoundary := func(t *testing.T, paths ...string) {
			t.Helper()
			h, closeRoot, e := masquerade(&cfg.Masquerade{Type: "file", Directory: root}, nil)
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(closeRoot)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", "https://ordinary/visible", nil))
			if w.Code != 200 || w.Body.String() != "visible" {
				t.Fatal("root did not serve its visible file", w.Code, w.Body.String())
			}
			for _, path := range paths {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest("GET", "https://ordinary"+path, nil))
				if w.Body.String() == "outside-secret" || w.Code == 200 {
					t.Fatal("root escaped", path, w.Code)
				}
				t.Logf("file boundary assertion completed: path=%s status=%d outside-secret=false", path, w.Code)
			}
		}
		t.Run("traversal", func(t *testing.T) {
			checkBoundary(t, "/../secret", "/%2e%2e/secret")
		})
		t.Run("symlink", func(t *testing.T) {
			createBoundarySymlink(t, target, filepath.Join(root, "escape"))
			checkBoundary(t, "/escape")
		})
	})
	t.Run("proxy", func(t *testing.T) {
		for _, secure := range []bool{false, true} {
			for _, rewrite := range []bool{false, true} {
				name := "http"
				if secure {
					name = "https"
				}
				if rewrite {
					name += "-rewrite"
				}
				t.Run(name, func(t *testing.T) {
					var upstreamHost string
					var calls atomic.Int64
					var mu sync.Mutex
					up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						upstreamHost = r.Host
						mu.Unlock()
						calls.Add(1)
						if r.Header.Get("Hysteria-Auth") != "" {
							t.Error("auth leaked")
						}
						w.Header().Set("Hysteria-UDP", "true")
						w.Header().Set("Hysteria-CC-RX", "auto")
						w.WriteHeader(233)
						io.WriteString(w, "upstream-body")
					}))
					if secure {
						up.StartTLS()
					} else {
						up.Start()
					}
					defer up.Close()
					h, cleanup, e := masquerade(&cfg.Masquerade{Type: "proxy", URL: up.URL, RewriteHost: rewrite, Insecure: secure}, (&net.Dialer{}).DialContext)
					if e != nil {
						t.Fatal(e)
					}
					r := httptest.NewRequest("POST", "https://original.example/auth", nil)
					r.Header.Set("Hysteria-Auth", "invalid")
					w := httptest.NewRecorder()
					h.ServeHTTP(w, r)
					if w.Code != 502 || w.Body.String() != "upstream-body" || w.Header().Get("Hysteria-UDP") != "" {
						t.Fatal("proxy forged admission", w.Code, w.Header())
					}
					mu.Lock()
					host := upstreamHost
					mu.Unlock()
					want := "original.example"
					if rewrite {
						u, _ := url.Parse(up.URL)
						want = u.Host
					}
					if host != want || calls.Load() != 1 {
						t.Fatal("Host", host, want)
					}
					cleanup()
					up.Close()
					w = httptest.NewRecorder()
					h.ServeHTTP(w, r)
					if w.Code != 502 {
						t.Fatal("upstream error", w.Code)
					}
					cleanup()
				})
			}
		}
	})
}
