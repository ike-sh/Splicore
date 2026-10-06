package operations

import (
	"bufio"
	"context"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func validOwner(i os.FileInfo) bool {
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return s.Uid == 0 || s.Uid == uint32(os.Geteuid()) || serviceOwner(s.Uid)
}
func serviceOwner(uid uint32) bool {
	i, err := os.Stat("/var/lib/splicore")
	if err != nil {
		return false
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	return ok && s.Uid != 0 && s.Uid == uid
}
func systemdCheck() application.Check {
	c := application.Check{Name: "systemd", Status: "info", Detail: "manager unavailable"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", "--quiet", "splicore.service")
	if cmd.Run() == nil {
		c.Status = "pass"
		c.Detail = "installed unit active"
	}
	return c
}

type journalReport struct {
	Available           bool           `json:"available"`
	Limit               int            `json:"limit"`
	Entries             int            `json:"entries"`
	Priorities          map[string]int `json:"priorities"`
	RawMessagesIncluded bool           `json:"raw_messages_included"`
}

func journalSummary(parent context.Context) journalReport {
	r := journalReport{Limit: 128, Priorities: map[string]int{}}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/journalctl", "--unit=splicore.service", "--no-pager", "--lines=128", "--output=json", "--output-fields=PRIORITY")
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return r
	}
	if cmd.Start() != nil {
		return r
	}
	scanner := bufio.NewScanner(pipe)
	scanner.Buffer(make([]byte, 4096), 65536)
	for scanner.Scan() {
		if r.Entries >= r.Limit {
			break
		}
		var e map[string]json.RawMessage
		if json.Unmarshal(scanner.Bytes(), &e) != nil {
			continue
		}
		var p string
		_ = json.Unmarshal(e["PRIORITY"], &p)
		p = enum(p, "0", "1", "2", "3", "4", "5", "6", "7")
		r.Priorities[p]++
		r.Entries++
	}
	// Kill malformed/unbounded producers before Wait; never propagate their text.
	if scanner.Err() != nil || r.Entries >= r.Limit {
		_ = cmd.Process.Kill()
	}
	r.Available = cmd.Wait() == nil || r.Entries == r.Limit
	return r
}
