package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/config"
	"github.com/sagernet/sing-box/internal/splicore/distribution"
	"github.com/sagernet/sing-box/internal/splicore/operations"
	"github.com/sagernet/sing-box/internal/splicore/storage/sqlite"
	"github.com/sagernet/sing-box/internal/splicore/transport"
	"io"
	"os"
	"time"
)

func operationsCLI(parent context.Context, args []string, out, errOut io.Writer, deps Dependencies) int {
	command, rest := args[0], args[1:]
	sub := ""
	if command != "support-bundle" {
		if len(rest) == 0 {
			return failure(errOut, fmt.Errorf("missing operation"))
		}
		sub, rest = rest[0], rest[1:]
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", distribution.ConfigPath, "")
	directory := fs.String("directory", "", "")
	output := fs.String("output", "", "")
	source := fs.String("source", "", "")
	artifact := fs.String("artifact", "", "")
	platform := fs.String("platform", "", "")
	start := fs.Bool("start", false, "")
	purge := fs.Bool("purge", false, "")
	if fs.Parse(rest) != nil || fs.NArg() != 0 {
		return failure(errOut, fmt.Errorf("invalid operation flags"))
	}
	// Reject irrelevant flags instead of silently accepting a destructive typo.
	allowed := map[string]bool{}
	switch command + "/" + sub {
	case "package/verify":
		allowed = map[string]bool{"directory": true, "platform": true}
	case "package/install":
		allowed = map[string]bool{"directory": true, "start": true}
	case "package/uninstall":
		allowed = map[string]bool{"purge": true}
	case "package/engine":
		allowed = map[string]bool{"artifact": true}
	case "state/backup":
		allowed = map[string]bool{"source": true, "output": true}
	case "service/initialize", "service/record-exit", "service/health", "service/recover-network":
		allowed = map[string]bool{"config": true}
	case "support-bundle/":
		allowed = map[string]bool{"config": true, "output": true}
	default:
		return failure(errOut, fmt.Errorf("unknown operation"))
	}
	valid := true
	fs.Visit(func(f *flag.Flag) {
		if !allowed[f.Name] {
			valid = false
		}
	})
	if !valid {
		return failure(errOut, fmt.Errorf("irrelevant operation flag"))
	}
	ctx, cancel := context.WithTimeout(parent, 180*time.Second)
	defer cancel()
	var err error
	if command == "package" {
		switch sub {
		case "verify":
			var m distribution.Manifest
			m, err = distribution.VerifyDirectory(*directory, *platform)
			if err == nil {
				return outputJSON(out, m)
			}
		case "install":
			err = distribution.Install(ctx, *directory, *start)
		case "uninstall":
			err = distribution.Uninstall(ctx, *purge)
		case "engine":
			err = distribution.InstallXray(ctx, *artifact)
		}
	} else if command == "state" {
		var schema int
		schema, err = sqlite.MaintenanceBackup(ctx, *source, *output)
		if err == nil {
			return outputJSON(out, struct {
				Schema   int  `json:"db_schema"`
				Snapshot bool `json:"snapshot"`
			}{schema, true})
		}
	} else {
		var c config.Config
		c, err = readConfig(*path)
		if err == nil {
			if command == "support-bundle" {
				client := transport.UnixClient(c.API.UnixSocket)
				defer client.Close()
				err = operations.SupportBundle(ctx, c, deps.Build, client, *output)
			} else {
				switch sub {
				case "initialize":
					err = operations.Initialize(c)
				case "record-exit":
					err = errors.Join(operations.RecoverHost(ctx, c), operations.RecordExit(c, deps.Build, os.Getenv("SERVICE_RESULT")))
				case "recover-network":
					err = operations.RecoverHost(ctx, c)
				case "health":
					err = distribution.Health(ctx, c, nil)
				}
			}
		}
	}
	if err != nil {
		return failure(errOut, err)
	}
	_, _ = fmt.Fprintln(out, "operation completed")
	return 0
}
