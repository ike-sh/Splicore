//go:build !linux

package distribution

import (
	"context"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/config"
)

func Install(context.Context, string, bool) error {
	return fmt.Errorf("service installation requires Linux")
}
func Uninstall(context.Context, bool) error { return fmt.Errorf("service uninstall requires Linux") }
func InstallXray(context.Context, string) error {
	return fmt.Errorf("engine installation requires Linux")
}
func Health(context.Context, config.Config, *Manifest) error {
	return fmt.Errorf("service health requires Linux")
}
