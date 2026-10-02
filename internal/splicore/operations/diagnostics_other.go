//go:build !linux

package operations

import (
	"context"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"os"
)

func validOwner(os.FileInfo) bool { return true }
func systemdCheck() application.Check {
	return application.Check{Name: "systemd", Status: "not_implemented", Detail: "Linux service only"}
}
func journalSummary(context.Context) any {
	return struct {
		Available bool `json:"available"`
	}{false}
}
