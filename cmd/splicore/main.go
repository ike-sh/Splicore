package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/sagernet/sing-box/internal/splicore/app"
	"github.com/sagernet/sing-box/internal/splicore/cli"
	"github.com/sagernet/sing-box/internal/splicore/version"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr, cli.Dependencies{Build: version.Current(), Serve: app.Serve}))
}
