package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ike-sh/Splicore/internal/splicore/app"
	"github.com/ike-sh/Splicore/internal/splicore/cli"
	"github.com/ike-sh/Splicore/internal/splicore/config"
	"github.com/ike-sh/Splicore/internal/splicore/version"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	serve := func(ctx context.Context, c config.Config) error {
		return app.ServeWithReady(ctx, c, func() error {
			_, err := fmt.Fprintln(os.Stderr, "Splicore ready")
			return err
		})
	}
	os.Exit(cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, cli.Dependencies{Build: version.Current(), Serve: serve, Check: app.Check}))
}
