package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/internal/splicore/cli"
	"github.com/sagernet/sing-box/internal/splicore/version"
)

func TestCommandIdentity(t *testing.T) {
	var out, errOut bytes.Buffer
	if cli.Run(context.Background(), []string{"version"}, &out, &errOut, cli.Dependencies{Build: version.Current()}) != 0 || !strings.Contains(out.String(), "Splicore devel") || !strings.Contains(out.String(), "Database Schema: 2") {
		t.Fatal("command identity", errOut.String())
	}
}
