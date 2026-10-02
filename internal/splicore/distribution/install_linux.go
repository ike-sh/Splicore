package distribution

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/config"
	"github.com/sagernet/sing-box/internal/splicore/storage/sqlite"
	"github.com/sagernet/sing-box/internal/splicore/transport"
	"github.com/sagernet/sing-box/internal/splicore/version"
	"golang.org/x/sys/unix"
)

// Installation is local and serialized independently from RuntimeDirectory.
// Paths are deliberately fixed: callers cannot supply a purge root.
func packageLock() (*os.File, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("package operations require root")
	}
	p := "/var/lib/.splicore-package.lock"
	if err := safePath(p, false); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	i, err := f.Stat()
	if err != nil || !i.Mode().IsRegular() || i.Mode().Perm() != 0600 || i.Sys().(*syscall.Stat_t).Uid != 0 {
		f.Close()
		return nil, fmt.Errorf("unsafe installation lock")
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another package operation is active")
	}
	return f, nil
}

func safePath(p string, required bool) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return fmt.Errorf("invalid installation path")
	}
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		current = filepath.Join(current, part)
		i, err := os.Lstat(current)
		if os.IsNotExist(err) && !required {
			return nil
		}
		if err != nil || i.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("missing or symlink installation path")
		}
		if current != p && !i.IsDir() {
			return fmt.Errorf("invalid installation parent")
		}
	}
	return nil
}

func command(ctx context.Context, name string, args ...string) error {
	c := exec.CommandContext(ctx, name, args...)
	c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	// Arbitrary subprocess output can contain configuration or secrets.
	if c.Run() != nil {
		return fmt.Errorf("local service operation failed")
	}
	return nil
}

func systemctl(ctx context.Context, args ...string) error {
	return command(ctx, "/usr/bin/systemctl", args...)
}

func serviceUser(ctx context.Context) (int, int, error) {
	u, err := user.Lookup("splicore")
	if _, absent := err.(user.UnknownUserError); absent {
		if err = command(ctx, "/usr/sbin/useradd", "--system", "--user-group", "--home-dir", StatePath, "--no-create-home", "--shell", "/usr/sbin/nologin", "splicore"); err != nil {
			return 0, 0, err
		}
		u, err = user.Lookup("splicore")
	}
	if err != nil {
		return 0, 0, fmt.Errorf("service user unavailable")
	}
	uid, e1 := strconv.Atoi(u.Uid)
	gid, e2 := strconv.Atoi(u.Gid)
	if e1 != nil || e2 != nil || uid <= 0 || gid <= 0 || u.HomeDir != StatePath {
		return 0, 0, fmt.Errorf("service user identity mismatch")
	}
	b, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return 0, 0, err
	}
	valid := false
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) == 7 && parts[0] == "splicore" {
			valid = parts[6] == "/usr/sbin/nologin" || parts[6] == "/sbin/nologin"
		}
	}
	g, err := user.LookupGroup("splicore")
	if !valid || err != nil || g.Gid != u.Gid {
		return 0, 0, fmt.Errorf("service user must have its dedicated group and non-login shell")
	}
	return uid, gid, nil
}

func ownedDirectory(p string, mode os.FileMode, uid, gid int) error {
	if err := safePath(p, false); err != nil {
		return err
	}
	if err := os.MkdirAll(p, mode); err != nil {
		return err
	}
	i, err := os.Lstat(p)
	if err != nil || !i.IsDir() {
		return fmt.Errorf("installation directory type mismatch")
	}
	if err = os.Chown(p, uid, gid); err != nil {
		return err
	}
	return os.Chmod(p, mode)
}

func atomicBytes(p string, b []byte, mode os.FileMode, uid, gid int) error {
	if err := safePath(p, false); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".splicore-replace-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(mode); err == nil {
		err = f.Chown(uid, gid)
	}
	if err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = f.Close()
	}
	if err == nil {
		err = os.Rename(f.Name(), p)
	}
	if err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(p))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func atomicCopy(src, dst string, mode os.FileMode, uid, gid int) error {
	if err := safePath(src, true); err != nil {
		return err
	}
	i, err := os.Lstat(src)
	if err != nil || !i.Mode().IsRegular() || i.Size() > 128<<20 {
		return fmt.Errorf("unsafe replacement source")
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return atomicBytes(dst, b, mode, uid, gid)
}

func marker(p string) error {
	if err := safePath(p, true); err != nil {
		return err
	}
	b, err := os.ReadFile(p)
	if err != nil || string(b) != Ownership {
		return fmt.Errorf("installation ownership marker missing")
	}
	return nil
}

func readBootstrap() (config.Config, error) {
	f, err := os.Open(ConfigPath)
	if err != nil {
		return config.Config{}, err
	}
	defer f.Close()
	c, err := config.Decode(f)
	if err != nil || c.StateDirectory != StatePath || c.KeyFile != StatePath+"/master.key" || c.API.UnixSocket != RuntimePath+"/splicore.sock" || c.Xray.RuntimeDirectory != RuntimePath+"/xray" {
		return c, fmt.Errorf("installed bootstrap layout mismatch")
	}
	return c, nil
}

func Health(ctx context.Context, c config.Config, expected *Manifest) error {
	client := transport.UnixClient(c.API.UnixSocket)
	defer client.Close()
	s, err := client.System(ctx)
	if err != nil || s.Health != "healthy" || s.DBSchema != version.DatabaseSchema || s.Foundation.PendingMigrations != 0 || s.Foundation.PendingTransactions != 0 {
		return fmt.Errorf("service health failed")
	}
	if expected != nil && (s.Version.Version != expected.Version || s.Version.Commit != expected.GitCommit || s.Version.SourceDigest != expected.SourceSHA256) {
		return fmt.Errorf("running service identity mismatch")
	}
	return nil
}

func existingInstallation() (*Manifest, error) {
	for _, p := range []string{BinaryPath, UnitPath, ReceiptPath, ConfigPath, StatePath, UpgradePath, "/etc/splicore"} {
		if err := safePath(p, false); err != nil {
			return nil, err
		}
	}
	_, err := os.Lstat("/etc/splicore/.owned")
	if os.IsNotExist(err) {
		if entries, e := os.ReadDir("/etc/splicore"); e == nil && len(entries) != 0 {
			return nil, fmt.Errorf("unowned nonempty configuration directory")
		}
		for _, p := range []string{BinaryPath, UnitPath, ReceiptPath, ConfigPath, StatePath, UpgradePath} {
			if _, e := os.Lstat(p); !os.IsNotExist(e) {
				return nil, fmt.Errorf("unowned installation paths already exist")
			}
		}
		return nil, nil
	}
	if err = marker("/etc/splicore/.owned"); err != nil {
		return nil, err
	}
	if err = marker(StatePath + "/.owned"); err != nil {
		return nil, err
	}
	if err = marker(UpgradePath + "/.owned"); err != nil {
		return nil, err
	}
	if _, err = readBootstrap(); err != nil {
		return nil, err
	}
	f, err := os.Open(ReceiptPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m, err := Decode(f)
	if err != nil {
		return nil, err
	}
	if _, err = os.Lstat(BinaryPath); os.IsNotExist(err) {
		return &m, nil
	}
	h, err := HashFile(BinaryPath)
	if err != nil || h != m.Files["splicore"].SHA256 {
		return nil, fmt.Errorf("installed binary differs from receipt")
	}
	h, err = HashFile(UnitPath)
	if err != nil || h != m.Files["splicore.service"].SHA256 {
		return nil, fmt.Errorf("installed unit differs from receipt")
	}
	return &m, nil
}

// Install stops before snapshotting SQLite. Every replacement is a same-directory
// fsync+rename. Health failure restores the original database, key and executable.
func Install(ctx context.Context, directory string, start bool) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("package operations require root")
	}
	m, err := VerifyDirectory(directory, "")
	if err != nil {
		return err
	}
	// The privileged copy phase must read only root-owned immutable staging.
	if err = filepath.Walk(directory, func(_ string, i os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		s, ok := i.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != 0 || i.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("package staging must be root-owned and not writable by others")
		}
		return nil
	}); err != nil {
		return err
	}
	build := version.Current()
	if build.Version != m.Version || build.Commit != m.GitCommit || build.SourceDigest != m.SourceSHA256 || build.Platform != m.GOOS+"/"+m.GOARCH || build.BuildTags != m.BuildTags || build.GoVersion != m.GoVersion || build.BuildTime != m.BuildTime || build.Dirty != m.SourceDirty {
		return fmt.Errorf("installer binary provenance differs from manifest")
	}
	lock, err := packageLock()
	if err != nil {
		return err
	}
	defer lock.Close()
	old, err := existingInstallation()
	if err != nil {
		return err
	}
	if old != nil && (old.DatabaseSchema < m.DatabaseMin || old.DatabaseSchema > m.DatabaseSchema) {
		return fmt.Errorf("unsupported upgrade schema boundary")
	}
	if err = safePath("/run/systemd/system", true); err != nil {
		return fmt.Errorf("systemd must be running")
	}
	uid, gid, err := serviceUser(ctx)
	if err != nil {
		return err
	}
	if err = ownedDirectory("/etc/splicore", 0750, 0, gid); err != nil {
		return err
	}
	if err = ownedDirectory(StatePath, 0700, uid, gid); err != nil {
		return err
	}
	if err = ownedDirectory(UpgradePath, 0700, 0, 0); err != nil {
		return err
	}
	if old == nil {
		if err = atomicBytes(UpgradePath+"/.owned", []byte(Ownership), 0600, 0, 0); err != nil {
			return err
		}
	}
	if err = safePath("/usr/local/bin", false); err != nil {
		return err
	}
	if err = os.MkdirAll("/usr/local/bin", 0755); err != nil {
		return err
	}
	// The shell entry deliberately uses umask 077; public program parents need
	// explicit final modes so the dedicated runtime user can traverse them.
	if err = os.Chmod("/usr/local/bin", 0755); err != nil {
		return err
	}
	if err = os.MkdirAll("/etc/systemd/system", 0755); err != nil {
		return err
	}
	if err = os.Chmod("/etc/systemd/system", 0755); err != nil {
		return err
	}
	wasActive := systemctl(ctx, "is-active", "--quiet", "splicore.service") == nil
	hasOldBinary := false
	if _, e := os.Lstat(BinaryPath); e == nil {
		hasOldBinary = true
	}
	backup := ""
	if old != nil && hasOldBinary {
		if err = systemctl(ctx, "stop", "splicore.service"); err != nil {
			return err
		}
		backup, err = os.MkdirTemp(UpgradePath, "transaction-")
		if err != nil {
			return err
		}
		// Backup is completed before any executable or database replacement.
		for name, src := range map[string]string{"splicore": BinaryPath, "splicore.service": UnitPath, "splicore.yaml": ConfigPath, "install.json": ReceiptPath} {
			if err = atomicCopy(src, filepath.Join(backup, name), 0600, 0, 0); err != nil {
				return restartOriginal(ctx, wasActive, err)
			}
		}
		if _, e := os.Lstat(StatePath + "/state.db"); e == nil {
			if err = atomicCopy(StatePath+"/master.key", filepath.Join(backup, "master.key"), 0600, 0, 0); err != nil {
				return restartOriginal(ctx, wasActive, err)
			}
			if _, err = sqlite.MaintenanceBackup(ctx, StatePath+"/state.db", filepath.Join(backup, "state.db")); err != nil {
				return restartOriginal(ctx, wasActive, err)
			}
		}
	}
	rollback := func(cause error) error {
		if backup == "" {
			if start || wasActive {
				recovery, cancel := context.WithTimeout(context.Background(), 45*time.Second)
				defer cancel()
				if systemctl(recovery, "stop", "splicore.service") != nil {
					return fmt.Errorf("candidate failed; service stop failed")
				}
			}
			return cause
		}
		// Caller cancellation must not interrupt recovery of the old service.
		recovery, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if e := systemctl(recovery, "stop", "splicore.service"); e != nil {
			return fmt.Errorf("upgrade failed; rollback stop failed; backup retained")
		}
		for name, dst := range map[string]string{"splicore": BinaryPath, "splicore.service": UnitPath, "splicore.yaml": ConfigPath, "install.json": ReceiptPath} {
			mode := os.FileMode(0600)
			ownerGroup := 0
			if name == "splicore" {
				mode = 0755
			}
			if name == "splicore.service" {
				mode = 0644
			}
			if name == "splicore.yaml" {
				mode = 0640
				ownerGroup = gid
			}
			if e := atomicCopy(filepath.Join(backup, name), dst, mode, 0, ownerGroup); e != nil {
				return fmt.Errorf("upgrade failed; file rollback failed; backup retained")
			}
		}
		if _, e := os.Lstat(filepath.Join(backup, "state.db")); e == nil {
			for _, suffix := range []string{"-wal", "-shm"} {
				p := StatePath + "/state.db" + suffix
				if e = safePath(p, false); e != nil {
					return fmt.Errorf("unsafe database rollback sidecar")
				}
				if e = os.Remove(p); e != nil && !os.IsNotExist(e) {
					return e
				}
			}
			for _, name := range []string{"master.key", "state.db"} {
				if e = atomicCopy(filepath.Join(backup, name), StatePath+"/"+name, 0600, uid, gid); e != nil {
					return fmt.Errorf("upgrade failed; database rollback failed; backup retained")
				}
			}
		}
		if systemctl(recovery, "daemon-reload") != nil || systemctl(recovery, "reset-failed", "splicore.service") != nil {
			return fmt.Errorf("upgrade failed; rollback unit reload failed")
		}
		if wasActive && systemctl(recovery, "start", "splicore.service") != nil {
			return fmt.Errorf("upgrade failed; original service could not restart")
		}
		return fmt.Errorf("upgrade rejected; original installation restored")
	}
	if old == nil {
		if err = atomicBytes("/etc/splicore/.owned", []byte(Ownership), 0600, 0, 0); err != nil {
			return err
		}
		if err = atomicBytes(StatePath+"/.owned", []byte(Ownership), 0600, uid, gid); err != nil {
			return err
		}
		if err = atomicCopy(filepath.Join(directory, "splicore.yaml"), ConfigPath, 0640, 0, gid); err != nil {
			return err
		}
	}
	if err = atomicCopy(filepath.Join(directory, "splicore"), BinaryPath, 0755, 0, 0); err != nil {
		return rollback(err)
	}
	if err = atomicCopy(filepath.Join(directory, "splicore.service"), UnitPath, 0644, 0, 0); err != nil {
		return rollback(err)
	}
	if err = systemctl(ctx, "daemon-reload"); err != nil {
		return rollback(err)
	}
	if err = systemctl(ctx, "enable", "splicore.service"); err != nil {
		return rollback(err)
	}
	if old == nil {
		b, e := json.MarshalIndent(m, "", "  ")
		if e != nil {
			return rollback(e)
		}
		if e = atomicBytes(ReceiptPath, append(b, '\n'), 0600, 0, 0); e != nil {
			return rollback(e)
		}
	}
	if start || wasActive {
		if err = systemctl(ctx, "reset-failed", "splicore.service"); err != nil {
			return rollback(err)
		}
		if err = systemctl(ctx, "start", "splicore.service"); err != nil {
			return rollback(err)
		}
		c, e := readBootstrap()
		if e != nil {
			return rollback(e)
		}
		health, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = Health(health, c, &m)
		cancel()
		if err != nil {
			return rollback(err)
		}
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return rollback(err)
	}
	if err = atomicBytes(ReceiptPath, append(b, '\n'), 0600, 0, 0); err != nil {
		return rollback(err)
	}
	return nil
}

func restartOriginal(ctx context.Context, active bool, cause error) error {
	if active {
		recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
		defer cancel()
		if systemctl(recovery, "start", "splicore.service") != nil {
			return fmt.Errorf("preflight backup failed; original restart failed")
		}
	}
	return cause
}

// Purge validates the complete fixed trees before deleting any files. Mounts,
// symlinks and foreign-owned members reject, including in upgrade backups.
func validateTree(p string, uid int) error {
	if err := safePath(p, true); err != nil {
		return err
	}
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return fmt.Errorf("purge mount inventory unavailable")
	}
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for _, line := range strings.Split(string(mounts), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 {
			mount := unescape.Replace(fields[4])
			if mount == p || strings.HasPrefix(mount, p+"/") {
				return fmt.Errorf("purge tree contains a mount")
			}
		}
	}
	i, err := os.Lstat(p)
	if err != nil {
		return err
	}
	dev := i.Sys().(*syscall.Stat_t).Dev
	return filepath.Walk(p, func(_ string, i os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		s, ok := i.Sys().(*syscall.Stat_t)
		if !ok || s.Dev != dev || s.Uid != 0 && s.Uid != uint32(uid) || i.Mode()&os.ModeSymlink != 0 || !i.IsDir() && !i.Mode().IsRegular() {
			return fmt.Errorf("unsafe purge tree")
		}
		return nil
	})
}

func Uninstall(ctx context.Context, purge bool) error {
	lock, err := packageLock()
	if err != nil {
		return err
	}
	defer lock.Close()
	m, err := existingInstallation()
	if err != nil {
		return err
	}
	if m == nil {
		return fmt.Errorf("no owned installation")
	}
	u, err := user.Lookup("splicore")
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil || uid <= 0 {
		return fmt.Errorf("invalid service user")
	}
	if purge {
		for _, p := range []string{"/etc/splicore", StatePath, UpgradePath} {
			if err = validateTree(p, uid); err != nil {
				return err
			}
		}
	}
	if err = systemctl(ctx, "stop", "splicore.service"); err != nil {
		return err
	}
	if err = systemctl(ctx, "disable", "splicore.service"); err != nil {
		return err
	}
	if purge {
		for _, p := range []string{"/etc/splicore", StatePath, UpgradePath} {
			if err = validateTree(p, uid); err != nil {
				return err
			}
		}
	}
	for _, p := range []string{BinaryPath, UnitPath} {
		if err = os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err = systemctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	if purge {
		for _, p := range []string{StatePath, UpgradePath, "/etc/splicore"} {
			if err = os.RemoveAll(p); err != nil {
				return err
			}
		}
	}
	// Retain the locked service identity: UID reuse must not expose retained state.
	return nil
}

// InstallXray accepts only the Phase 6 Linux reference bytes. No network access.
func InstallXray(ctx context.Context, artifact string) error {
	lock, err := packageLock()
	if err != nil {
		return err
	}
	defer lock.Close()
	m, err := existingInstallation()
	if err != nil || m == nil {
		return fmt.Errorf("owned Splicore installation required")
	}
	if m.GOARCH != "amd64" {
		return fmt.Errorf("Xray artifact not qualified for this platform")
	}
	if err = safePath(artifact, true); err != nil {
		return err
	}
	h, err := HashFile(artifact)
	if err != nil || h != XrayHashes["linux/amd64"] {
		return fmt.Errorf("Xray artifact checksum mismatch")
	}
	uid, gid, err := serviceUser(ctx)
	if err != nil {
		return err
	}
	dir := StatePath + "/engines/xray-artifact"
	if err = ownedDirectory(StatePath+"/engines", 0700, uid, gid); err != nil {
		return err
	}
	if err = ownedDirectory(dir, 0750, 0, gid); err != nil {
		return err
	}
	dst := dir + "/xray-26.3.27"
	if err = atomicCopy(artifact, dst, 0750, 0, gid); err != nil {
		return err
	}
	// Verify the private copied bytes, never rely only on a mutable source path.
	h, err = HashFile(dst)
	if err != nil || h != XrayHashes["linux/amd64"] {
		return fmt.Errorf("copied Xray checksum mismatch")
	}
	return nil
}
