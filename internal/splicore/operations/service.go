// Package operations owns local service initialization and sanitized exit records.
package operations

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/config"
	"github.com/ike-sh/Splicore/internal/splicore/secretvault"
	"github.com/ike-sh/Splicore/internal/splicore/version"
)

func Initialize(c config.Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.KeyFile == "" {
		return fmt.Errorf("service requires an explicit key file")
	}
	if err := PrivateDirectory(c.StateDirectory); err != nil {
		return err
	}
	if err := PrivateDirectory(filepath.Dir(c.API.UnixSocket)); err != nil {
		return err
	}
	_, dbErr := os.Lstat(filepath.Join(c.StateDirectory, "state.db"))
	_, keyErr := os.Lstat(c.KeyFile)
	if os.IsNotExist(keyErr) {
		if !os.IsNotExist(dbErr) {
			return fmt.Errorf("existing database requires its original master key")
		}
		if err := secretvault.InitFile(c.KeyFile); err != nil {
			return err
		}
	}
	_, err := secretvault.LoadFile(c.KeyFile)
	return err
}

// NotifyReady only communicates with systemd's inherited local notification socket.
func NotifyReady() error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return nil
	}
	if path[0] != '/' && path[0] != '@' {
		return fmt.Errorf("invalid notification socket")
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("service notification unavailable")
	}
	defer c.Close()
	_, err = c.Write([]byte("READY=1"))
	return err
}

type ExitRecord struct {
	Schema         int    `json:"schema"`
	Version        string `json:"version"`
	Commit         string `json:"commit"`
	Component      string `json:"component"`
	Engine         string `json:"engine"`
	Protocol       string `json:"protocol"`
	Timestamp      string `json:"timestamp"`
	Classification string `json:"classification"`
}

func ExitClass(s string) string {
	switch s {
	case "success", "exit-code", "signal", "core-dump", "timeout", "watchdog", "resources", "start-limit-hit", "oom-kill", "exec-condition":
		return s
	default:
		return "unknown"
	}
}
func RecordExit(c config.Config, v version.Info, result string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	dir := filepath.Join(c.StateDirectory, "crashes")
	if err := PrivateDirectory(dir); err != nil {
		return err
	}
	lock, err := recordLock(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	r := ExitRecord{Schema: 1, Version: v.Version, Commit: v.Commit, Component: "process", Engine: "native", Protocol: "none", Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Classification: ExitClass(result)}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "exit-*.json")
	if err != nil {
		return err
	}
	name := f.Name()
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(name)
		}
	}()
	if _, err = f.Write(append(data, '\n')); err == nil {
		err = f.Sync()
	}
	if err != nil {
		return err
	}
	ok = true
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type record struct {
		name string
		at   time.Time
	}
	var records []record
	for _, e := range entries {
		if len(e.Name()) > 10 && e.Name()[:5] == "exit-" && filepath.Ext(e.Name()) == ".json" {
			i, e2 := e.Info()
			if e2 != nil || !i.Mode().IsRegular() {
				return fmt.Errorf("unsafe crash record")
			}
			records = append(records, record{e.Name(), i.ModTime()})
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].at.Equal(records[j].at) {
			return records[i].name < records[j].name
		}
		return records[i].at.Before(records[j].at)
	})
	for len(records) > 16 {
		if err = os.Remove(filepath.Join(dir, records[0].name)); err != nil {
			return err
		}
		records = records[1:]
	}
	return nil
}
