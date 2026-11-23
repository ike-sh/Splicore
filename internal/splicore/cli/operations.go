package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/config"
	"github.com/ike-sh/Splicore/internal/splicore/distribution"
	"github.com/ike-sh/Splicore/internal/splicore/operations"
	"github.com/ike-sh/Splicore/internal/splicore/storage/sqlite"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
	"github.com/ike-sh/Splicore/internal/splicore/version"
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
	platform := fs.String("platform", "", "")
	start := fs.Bool("start", false, "")
	purge := fs.Bool("purge", false, "")
	acknowledgeCurrentState := fs.Bool("acknowledge-current-state", false, "")
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
	case "state/backup":
		allowed = map[string]bool{"source": true, "output": true}
	case "state/integrity":
		allowed = map[string]bool{"source": true}
	case "state/establish-witness":
		allowed = map[string]bool{"source": true, "acknowledge-current-state": true}
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
		}
	} else if command == "state" {
		switch sub {
		case "backup":
			var schema int
			schema, err = sqlite.MaintenanceBackup(ctx, *source, *output)
			if err == nil {
				witnessStatus := "witness_missing"
				historicalProof := false
				if schema == version.DatabaseSchema {
					var inspection sqlite.WitnessInspection
					inspection, err = sqlite.InspectCommitWitness(ctx, *output)
					if err == nil {
						witnessStatus, historicalProof = inspection.Status, inspection.HistoricalProof
					}
				}
				if err == nil {
					return outputJSON(out, struct {
						Schema          int    `json:"db_schema"`
						Snapshot        bool   `json:"snapshot"`
						WitnessStatus   string `json:"witness_status"`
						HistoricalProof bool   `json:"historical_proof"`
					}{schema, true, witnessStatus, historicalProof})
				}
			}
		case "integrity":
			var inspection sqlite.WitnessInspection
			inspection, err = sqlite.InspectCommitWitness(ctx, *source)
			if err == nil {
				return outputJSON(out, inspection)
			}
		case "establish-witness":
			var inspection sqlite.WitnessInspection
			inspection, err = sqlite.EstablishCommitWitness(ctx, *source, *acknowledgeCurrentState)
			if err == nil {
				return outputJSON(out, inspection)
			}
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
