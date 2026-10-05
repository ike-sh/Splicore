package cli

import (
	"context"
	"flag"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	"github.com/sagernet/sing-box/internal/splicore/secretvault"
	"github.com/sagernet/sing-box/internal/splicore/transport"
	"io"
	"os"
)

func boundedFile(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, identity.Err(identity.Unavailable, "input file unavailable")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(b) > 65536 {
		return nil, identity.Err(identity.Invalid, "input file exceeds limit")
	}
	return b, nil
}
func inboundCLI(ctx context.Context, args []string, out, errOut io.Writer, deps Dependencies) int {
	if len(args) < 2 {
		return failure(errOut, identity.Err(identity.Invalid, "subcommand required"))
	}
	fs := flag.NewFlagSet("inbound", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg := fs.String("config", "", "bootstrap file")
	file := fs.String("file", "", "canonical document")
	plan := fs.String("plan", "", "saved plan")
	id := fs.String("id", "", "inbound ID")
	format := fs.String("format", "", "client format")
	client := fs.String("client-version", "", "pinned client version")
	protocol := fs.String("protocol", "snell", "registered protocol command")
	binding := fs.String("binding-id", "", "explicit user binding for export")
	if fs.Parse(args[2:]) != nil || fs.NArg() != 0 {
		return failure(errOut, identity.Err(identity.Invalid, "invalid arguments"))
	}
	if args[0] == "key" {
		if args[1] != "init" || *file == "" {
			return failure(errOut, identity.Err(identity.Invalid, "key init --file required"))
		}
		if e := secretvault.InitFile(*file); e != nil {
			return failure(errOut, e)
		}
		return outputJSON(out, map[string]bool{"initialized": true})
	}
	if args[1] == "validate" {
		b, e := boundedFile(*file)
		if e == nil {
			p, engines, _, er := registry.NativeCore()
			e = er
			if e == nil {
				_, e = p.DecodeCreation(engines, *protocol, b)
			}
		}
		if e != nil {
			return failure(errOut, e)
		}
		return outputJSON(out, map[string]bool{"valid": true})
	}
	s, ok := deps.Queries.(application.InboundCommands)
	if !ok {
		if *cfg == "" {
			return failure(errOut, identity.Err(identity.Invalid, "explicit bootstrap file required"))
		}
		c, e := readConfig(*cfg)
		if e != nil {
			return failure(errOut, e)
		}
		ctl := transport.UnixClient(c.API.UnixSocket)
		defer ctl.Close()
		s = ctl
	}
	var result any
	var err error
	commands, creationAvailable := s.(application.CreationCommands)
	bindings, bindingAvailable := s.(application.BindingCommands)
	switch args[1] {
	case "list":
		result, err = s.Inbounds(ctx)
	case "plan":
		var b []byte
		b, err = boundedFile(*file)
		if err == nil {
			if !creationAvailable {
				err = identity.Err(identity.NotImplemented, "creation unavailable")
			} else {
				result, err = commands.PlanCreation(ctx, *protocol, b)
			}
		}
	case "apply":
		var b, p []byte
		b, err = boundedFile(*file)
		if err == nil {
			p, err = boundedFile(*plan)
		}
		var planned application.CreationPlan
		if err == nil {
			err = application.StrictJSON(p, &planned)
		}
		if err == nil {
			if !creationAvailable {
				err = identity.Err(identity.NotImplemented, "creation unavailable")
			} else {
				result, err = commands.ApplyCreation(ctx, *protocol, application.ApplyRequest{Document: b, Digest: planned.Digest, Revision: planned.Revision})
			}
		}
	case "get", "export", "display", "binding":
		var parsed identity.ID
		parsed, err = identity.ParseID(*id)
		if err == nil {
			switch args[1] {
			case "get":
				result, err = s.Inbound(ctx, parsed)
			case "export":
				var bid identity.ID
				if *binding != "" {
					bid, err = identity.ParseID(*binding)
				}
				if err == nil {
					result, err = s.ExportClient(ctx, parsed, application.ExportRequest{Format: ports.Format(*format), ClientVersion: *client, BindingID: bid})
				}
			case "display":
				var b []byte
				b, err = boundedFile(*file)
				var r application.DisplayRequest
				if err == nil {
					err = application.StrictJSON(b, &r)
				}
				if err == nil {
					result, err = s.SetDisplay(ctx, parsed, r)
				}
			case "binding":
				if !bindingAvailable {
					err = identity.Err(identity.NotImplemented, "binding mutation unavailable")
					break
				}
				var b []byte
				b, err = boundedFile(*file)
				var req application.BindingRequest
				if err == nil {
					err = application.StrictJSON(b, &req)
				}
				if err == nil {
					result, err = bindings.SetBinding(ctx, parsed, req)
				}
			}
		}
	default:
		err = identity.Err(identity.Invalid, "unknown inbound command")
	}
	if err != nil {
		return failure(errOut, err)
	}
	return outputJSON(out, result)
}
