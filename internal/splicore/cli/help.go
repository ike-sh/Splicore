package cli

import (
	"fmt"
	"io"
)

const usage = `Splicore — single-process server and client network core

Usage:
  splicore help [command]                  Offline command help
  splicore version [--json]                Build identity and features
  splicore check --config <bootstrap>      Offline validation; no listeners
    [--protocol <name> --file <inbound.json>]
  splicore validate <bootstrap>            Bootstrap schema validation (legacy)
  splicore run --config <bootstrap>        Start the core in the foreground
  splicore stop --config <bootstrap>       Request graceful core shutdown
  splicore status --config <bootstrap>     Query the running core
  splicore capabilities --config <file>    Query compiled protocol capabilities
  splicore doctor [--config <bootstrap>]   Passive diagnostics
  splicore key init --file <master.key>    Provision a new private vault key

Managed resources (use --config for the local control endpoint):
  inbound validate|plan|apply --protocol <name> --file <document> [--plan <plan>]
  inbound list|get|export|display|binding
  node, outbound, local-inbound, local-binding, route
  client status|validate|plan|apply|start|stop|restart
  network, route-rule, rule-set, policy, dns, tun
  provider, ruleset-provider, node import|import-uri|export|batch|apply
  service, state, package, support-bundle

The schema-1 YAML bootstrap selects state_directory, key_file and api.unix_socket.
Proxy settings are canonical JSON managed through the local API and stored in
SQLite. check validates committed state when present; --protocol/--file checks
an additional inbound document, including referenced TLS files. It never binds
ports, probes remote destinations or changes system networking.
Linux uses a private Unix socket. Windows uses a local owner-restricted named
pipe derived from api.unix_socket and the current user; no TCP control listener.
Stop with Ctrl+C/SIGTERM or the stop command. Foreground logs use stderr;
installed Linux services use journald. Exit 0 means success; exit 1 means failure.
See docs/CLI.md and docs/CONFIGURATION.md for resource formats and platform limits.
`

func help(args []string, out, errOut io.Writer) int {
	if len(args) > 2 || len(args) == 2 && args[0] != "help" {
		_, _ = fmt.Fprintln(errOut, "usage: splicore help [command]")
		return 1
	}
	if len(args) == 2 {
		switch args[1] {
		case "version", "check", "validate", "run", "stop", "status", "doctor", "capabilities", "key", "inbound", "node", "outbound", "local-inbound", "local-binding", "route", "client", "network", "route-rule", "rule-set", "policy", "dns", "tun", "provider", "ruleset-provider", "service", "state", "package", "support-bundle":
		default:
			_, _ = fmt.Fprintln(errOut, "unknown help topic; use splicore help")
			return 1
		}
	}
	if _, err := io.WriteString(out, usage); err != nil {
		return 1
	}
	return 0
}
