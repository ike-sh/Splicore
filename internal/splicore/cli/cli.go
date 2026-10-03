// Package cli invokes application queries and commands without SQL or protocol access.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/config"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/operations"
	"github.com/sagernet/sing-box/internal/splicore/transport"
	"github.com/sagernet/sing-box/internal/splicore/version"
)

type Dependencies struct {
	Build   version.Info
	Queries application.Queries
	Serve   func(context.Context, config.Config) error
}

func Run(ctx context.Context, args []string, out, errOut io.Writer, deps Dependencies) int {
	if len(args) > 0 && (args[0] == "network" || args[0] == "policy" || args[0] == "dns" || args[0] == "rule-set" || args[0] == "route-rule" || args[0] == "route" && len(args) > 1 && (args[1] == "explain" || args[1] == "status")) {
		return networkCLI(ctx, args, out, errOut, deps)
	}
	if len(args) > 0 && (args[0] == "client" || args[0] == "node" || args[0] == "outbound" || args[0] == "local-inbound" || args[0] == "route") {
		return clientCLI(ctx, args, out, errOut, deps)
	}
	if len(args) > 0 && (args[0] == "service" || args[0] == "state" || args[0] == "package" || args[0] == "support-bundle") {
		return operationsCLI(ctx, args, out, errOut, deps)
	}
	if len(args) > 0 && (args[0] == "inbound" || args[0] == "key") {
		return inboundCLI(ctx, args, out, errOut, deps)
	}
	if len(args) == 0 {
		_, _ = fmt.Fprintln(out, "Splicore foundation: version | status | doctor | capabilities | validate <file> | run --config <file>")
		return 0
	}
	if args[0] == "version" {
		if len(args) == 2 && args[1] == "--json" {
			return outputJSON(out, deps.Build)
		}
		if len(args) != 1 {
			return failure(errOut, identity.Err(identity.Invalid, "version takes no arguments"))
		}
		return printVersion(out, deps.Build)
	}
	if args[0] == "validate" {
		if len(args) != 2 {
			return failure(errOut, identity.Err(identity.Invalid, "validate requires one bootstrap file"))
		}
		if _, err := readConfig(args[1]); err != nil {
			return failure(errOut, err)
		}
		_, _ = fmt.Fprintln(out, "valid bootstrap schema 1")
		return 0
	}
	fs := flag.NewFlagSet("splicore", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", "", "bootstrap config path")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 {
		return failure(errOut, identity.Err(identity.Invalid, "invalid command arguments"))
	}
	c := config.Default()
	if *path != "" {
		var err error
		c, err = readConfig(*path)
		if err != nil {
			return failure(errOut, err)
		}
	}
	if args[0] == "run" {
		if *path == "" || deps.Serve == nil {
			return failure(errOut, identity.Err(identity.Invalid, "run requires explicit --config bootstrap file"))
		}
		if err := deps.Serve(ctx, c); err != nil {
			return failure(errOut, err)
		}
		return 0
	}
	queries := deps.Queries
	if queries == nil {
		if !transport.ProductionSupported() {
			if args[0] == "status" {
				_, _ = fmt.Fprintln(out, "not running")
				return 0
			}
			if args[0] == "doctor" {
				return offlineDoctor(ctx, out, c, deps.Build, nil)
			}
			return failure(errOut, identity.Err(identity.NotImplemented, "use Linux local control or Windows httptest development transport"))
		}
		client := transport.UnixClient(c.API.UnixSocket)
		defer client.Close()
		queries = client
	}
	switch args[0] {
	case "status":
		result, err := queries.System(ctx)
		if errors.Is(err, transport.ErrNotRunning) {
			_, _ = fmt.Fprintln(out, "not running")
			return 0
		}
		if err != nil {
			return failure(errOut, err)
		}
		return outputJSON(out, result)
	case "capabilities":
		result, err := queries.Capabilities(ctx, "", 200)
		if err != nil {
			return failure(errOut, err)
		}
		return outputJSON(out, result)
	case "doctor":
		return offlineDoctor(ctx, out, c, deps.Build, queries)
	default:
		return failure(errOut, identity.Err(identity.Invalid, "unknown command"))
	}
}

func printVersion(out io.Writer, v version.Info) int {
	_, err := fmt.Fprintf(out, "%s %s\nCommit: %s (dirty: %t)\nBuild Time: %s\nGo: %s\nPlatform: %s\nUpstream Baseline: sing-box %s (%s)\nConfig Schema: %d\nDatabase Schema: %d\nProtocol ABI: %d\nAPI: %s\n", v.Product, v.Version, v.Commit, v.Dirty, v.BuildTime, v.GoVersion, v.Platform, v.UpstreamTag, v.UpstreamCommit, version.ConfigSchema, version.DatabaseSchema, version.ProtocolABI, v.APIVersion)
	if err != nil {
		return 1
	}
	return 0
}

func readConfig(path string) (config.Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return config.Config{}, identity.Err(identity.Unavailable, "cannot read bootstrap file")
	}
	defer f.Close()
	return config.Decode(f)
}

func offlineDoctor(ctx context.Context, out io.Writer, c config.Config, v version.Info, q application.Queries) int {
	d := application.Doctor{Version: v, Checks: []application.Check{{Name: "platform", Status: "pass", Detail: runtime.GOOS + "/" + runtime.GOARCH}}}
	d.Checks = append(d.Checks, operations.PathChecks(c)...)
	if info, err := os.Stat(c.StateDirectory); err == nil && info.IsDir() {
		d.Checks = append(d.Checks, application.Check{Name: "storage_path", Status: "pass", Detail: "directory exists"})
	} else {
		d.Checks = append(d.Checks, application.Check{Name: "storage_path", Status: "info", Detail: "directory absent or inaccessible"})
	}
	if _, err := os.Stat(filepath.Join(c.StateDirectory, "state.db")); err != nil {
		d.Checks = append(d.Checks, application.Check{Name: "database", Status: "info", Detail: "database absent or inaccessible"})
	} else {
		d.Checks = append(d.Checks, application.Check{Name: "database", Status: "info", Detail: "file exists; offline integrity not inspected"})
	}
	if q == nil {
		d.Checks = append(d.Checks, application.Check{Name: "api_transport", Status: "not_implemented", Detail: "Linux UDS production transport; Windows httptest only"})
		return outputJSON(out, d)
	}
	system, err := q.System(ctx)
	if err != nil {
		detail := "control service unavailable"
		if errors.Is(err, transport.ErrNotRunning) {
			detail = "not running"
		}
		d.Checks = append(d.Checks, application.Check{Name: "api_transport", Status: "info", Detail: detail})
		return outputJSON(out, d)
	}
	d.Checks = append(d.Checks, application.Check{Name: "api_transport", Status: "pass", Detail: "application response received"}, application.Check{Name: "db_schema", Status: "pass", Detail: fmt.Sprint(system.DBSchema)}, application.Check{Name: "foundation_health", Status: "info", Detail: system.Health})
	d.Checks = append(d.Checks, operations.ClientDoctorChecks(system.ClientRuntime)...)
	d.Checks = append(d.Checks, application.Check{Name: "database", Status: "pass", Detail: system.Foundation.DatabaseStatus}, application.Check{Name: "migrations", Status: "info", Detail: fmt.Sprint(system.Foundation.PendingMigrations) + " pending"}, application.Check{Name: "transactions", Status: "info", Detail: fmt.Sprint(system.Foundation.PendingTransactions) + " pending"}, application.Check{Name: "engine_registry", Status: "pass", Detail: fmt.Sprint(system.Foundation.Engines) + " engine entries"}, application.Check{Name: "exporter_registry", Status: "pass", Detail: fmt.Sprint(system.Foundation.Exporters) + " compiled exporters"})
	page, err := q.Capabilities(ctx, "", 200)
	if err == nil {
		d.Checks = append(d.Checks, application.Check{Name: "protocol_registry", Status: "pass", Detail: fmt.Sprint(len(page.Items)) + " declared entries"})
	}
	return outputJSON(out, d)
}

func outputJSON(out io.Writer, v any) int {
	if json.NewEncoder(out).Encode(v) != nil {
		return 1
	}
	return 0
}

func failure(out io.Writer, err error) int {
	var e *identity.Error
	message := "foundation operation failed"
	if errors.As(err, &e) { // Known domain errors contain no user input; callers cannot smuggle text through transports.
		message = string(e.Code) + ": command rejected"
		if e.Code == identity.PortConflict {
			message = "port_conflict: listener port is already in use"
		}
	}
	_, _ = fmt.Fprintln(out, message)
	return 1
}
