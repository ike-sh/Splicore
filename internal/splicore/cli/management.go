package cli

import (
	"context"
	"flag"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/provider"
	"github.com/sagernet/sing-box/internal/splicore/transport"
	"io"
	"os"
)

func managementInput(path string, stdin bool) ([]byte, error) {
	var reader io.Reader = os.Stdin
	if !stdin {
		if path == "" {
			return nil, identity.Err(identity.Invalid, "file or stdin required")
		}
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() || info.Size() > provider.MaxBody {
			return nil, identity.Err(identity.Invalid, "regular bounded import file required")
		}
		f, e := os.Open(path)
		if e != nil {
			return nil, identity.Err(identity.Unavailable, "input unavailable")
		}
		defer f.Close()
		after, e := f.Stat()
		if e != nil || !os.SameFile(info, after) || !after.Mode().IsRegular() {
			return nil, identity.Err(identity.Invalid, "input file changed")
		}
		reader = f
	} else if path != "" {
		return nil, identity.Err(identity.Invalid, "choose file or stdin")
	}
	b, e := io.ReadAll(io.LimitReader(reader, provider.MaxBody+1))
	if e != nil || len(b) > provider.MaxBody {
		return nil, identity.Err(identity.Invalid, "input limit")
	}
	return b, nil
}
func managementCLI(ctx context.Context, args []string, out, errOut io.Writer, deps Dependencies) int {
	if len(args) < 2 {
		return failure(errOut, identity.Err(identity.Invalid, "management subcommand required"))
	}
	fs := flag.NewFlagSet("management", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg := fs.String("config", "", "bootstrap file")
	file := fs.String("file", "", "regular input file")
	stdin := fs.Bool("stdin", false, "secret input from stdin")
	planFile := fs.String("plan", "", "saved preview token to apply")
	id := fs.String("id", "", "immutable ID")
	format := fs.String("format", "canonical", "import/export format")
	mode := fs.String("mode", "strict", "strict or lenient")
	engine := fs.String("engine", "native", "outbound engine")
	generate := fs.Bool("generate-outbounds", false, "generate stable outbounds")
	owner := fs.String("provider-id", "", "export provider nodes")
	all := fs.Bool("all", false, "export all nodes")
	reveal := fs.Bool("reveal-secrets", false, "explicit client secret export")
	version := fs.String("client-version", "", "export client version")
	if fs.Parse(args[2:]) != nil || fs.NArg() != 0 {
		return failure(errOut, identity.Err(identity.Invalid, "invalid management arguments"))
	}
	// Existing node CRUD applies carry the original mutation document. Import
	// plans carry only the single-use management token, without a --file document.
	if args[0] == "node" && args[1] == "apply" && *file != "" {
		return clientCLI(ctx, args, out, errOut, deps)
	}
	commands, ok := deps.Queries.(application.ManagementCommands)
	if !ok {
		if *cfg == "" {
			return failure(errOut, identity.Err(identity.Invalid, "explicit bootstrap required"))
		}
		c, e := readConfig(*cfg)
		if e != nil {
			return failure(errOut, e)
		}
		ctl := transport.UnixClient(c.API.UnixSocket)
		defer ctl.Close()
		commands = ctl
	}
	var result any
	var e error
	if args[0] != "node" && *id != "" && *planFile == "" && args[1] != "apply" && args[1] != "create" {
		query, ok := commands.(application.ClientCommands)
		if !ok {
			return failure(errOut, identity.Err(identity.Unavailable, "provider query unavailable"))
		}
		status, err := query.ClientStatus(ctx)
		if err != nil {
			return failure(errOut, err)
		}
		kind := "proxy"
		if args[0] == "ruleset-provider" {
			kind = "ruleset"
		}
		found := false
		for _, p := range status.State.Management.Providers {
			found = found || string(p.ID) == *id && p.Kind == kind
		}
		if !found {
			return failure(errOut, identity.Err(identity.NotFound, "provider not found"))
		}
	}
	switch {
	case args[1] == "apply" || *planFile != "":
		b, err := managementInput(*planFile, false)
		if err != nil {
			return failure(errOut, err)
		}
		var p application.ManagementPreview
		e = application.StrictManagementJSON(b, &p)
		if e == nil {
			result, e = commands.ApplyManagement(ctx, application.ManagementApply{Token: p.Token, Revision: p.Revision})
		}
	case args[0] == "node" && args[1] == "export":
		req := application.NodeExportRequest{Format: *format, ProviderID: identity.ID(*owner), All: *all, RevealSecrets: *reveal, ClientVersion: *version}
		if *id != "" {
			req.IDs = []identity.ID{identity.ID(*id)}
		}
		var exported application.NodeExport
		exported, e = commands.ExportNodes(ctx, req)
		if e == nil {
			for _, d := range exported.Details {
				_, _ = fmt.Fprintf(errOut, "%s: server version %d, client wire version %d; %s\n", d.NodeID, d.Description.ServerVersion, d.Description.ClientWireVersion, d.Description.Compatibility)
			}
			_, e = fmt.Fprintln(out, exported.Content)
			if e == nil {
				return 0
			}
		}
	case args[0] != "node" && (args[1] == "refresh" || args[1] == "refresh-preview"):
		if args[1] == "refresh" {
			result, e = commands.RefreshProvider(ctx, identity.ID(*id))
		} else {
			result, e = commands.PreviewProviderRefresh(ctx, identity.ID(*id))
		}
	case args[0] != "node" && (args[1] == "list" || args[1] == "get"):
		query, ok := commands.(application.ClientCommands)
		if !ok {
			return failure(errOut, identity.Err(identity.Unavailable, "provider query unavailable"))
		}
		status, err := query.ClientStatus(ctx)
		e = err
		if e == nil {
			kind := "proxy"
			if args[0] == "ruleset-provider" {
				kind = "ruleset"
			}
			items := []provider.Provider{}
			for _, p := range status.State.Management.Providers {
				if p.Kind == kind && (args[1] == "list" || string(p.ID) == *id) {
					items = append(items, p)
				}
			}
			result = items
			if args[1] == "get" {
				if len(items) != 1 {
					e = identity.Err(identity.NotFound, "provider not found")
				} else {
					result = items[0]
				}
			}
		}
	default:
		req := application.ManagementRequest{}
		if args[0] == "node" && (args[1] == "import" || args[1] == "import-uri") {
			b, err := managementInput(*file, *stdin)
			if err != nil {
				return failure(errOut, err)
			}
			req = application.ManagementRequest{Operation: "import", InputFormat: *format, Content: string(b), Mode: *mode, GenerateOutbounds: *generate, Engine: *engine}
			if args[1] == "import-uri" {
				req.InputFormat = "uri"
			}
		} else {
			if args[1] == "delete" {
				req.Operation = "provider-delete"
				req.ID = identity.ID(*id)
			} else {
				b, err := managementInput(*file, *stdin)
				if err != nil {
					return failure(errOut, err)
				}
				e = application.StrictManagementJSON(b, &req)
				if e != nil {
					return failure(errOut, e)
				}
				if args[0] == "node" && args[1] == "batch" {
					if req.Operation != "batch" {
						return failure(errOut, identity.Err(identity.Invalid, "batch command required"))
					}
				} else if args[1] == "create" || args[1] == "update" {
					req.Operation = "provider-upsert"
					req.ID = identity.ID(*id)
					kind := "proxy"
					if args[0] == "ruleset-provider" {
						kind = "ruleset"
					}
					if req.Provider == nil || req.Provider.Kind != kind {
						return failure(errOut, identity.Err(identity.Invalid, "provider kind mismatch"))
					}
				} else {
					return failure(errOut, identity.Err(identity.Invalid, "unknown management command"))
				}
			}
		}
		result, e = commands.PreviewManagement(ctx, req)
	}
	if e != nil {
		return failure(errOut, e)
	}
	return outputJSON(out, result)
}
