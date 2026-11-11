package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/api"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

func TestSnellUDPConflictPreservesServerAPIAndExplicitRecovery(t *testing.T) {
	ctx := context.Background()
	s, store := setupSnell(t, filepath.Join(t.TempDir(), "state", "state.db"), nil)
	defer stop(t, s, store)
	enableClient(t, s)
	existing := apply(t, s, doc(freePort(t), 5))
	apiServer := httptest.NewServer(api.Handler(s))
	defer apiServer.Close()
	before, err := store.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	address := fmt.Sprintf("127.0.0.1:%d", port)
	owner, err := net.ListenPacket("udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	draft := json.RawMessage(strings.ReplaceAll(string(doc(port, 5)), "synthetic-", "second-"))
	plan, err := s.PlanSnell(ctx, draft)
	if err != nil {
		t.Fatal(err)
	}
	req := application.ApplyRequest{Document: draft, Digest: plan.Digest, Revision: plan.Revision}
	_, err = s.ApplySnell(ctx, req)
	var domain *identity.Error
	var op *net.OpError
	if !errors.Is(err, syscall.EADDRINUSE) || !errors.As(err, &domain) || domain.Code != identity.PortConflict || !errors.As(err, &op) || op.Net != "udp" || op.Addr.String() != address {
		t.Fatal("UDP bind cause or classification lost", err)
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	response, err := apiServer.Client().Post(apiServer.URL+"/api/v1/snell/apply", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	problemBody, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	var problem api.Problem
	if err != nil || response.StatusCode != http.StatusConflict || json.Unmarshal(problemBody, &problem) != nil || problem.Code != identity.PortConflict || bytes.Contains(problemBody, []byte("bind:")) || bytes.Contains(problemBody, []byte(address)) {
		t.Fatal("API domain mapping/redaction changed", response.StatusCode, string(problemBody), err)
	}
	after, err := store.State(ctx)
	if err != nil || after.Revision != before.Revision || after.PendingTransactions != 0 {
		t.Fatal("failed candidate changed committed state", err)
	}
	page, err := s.Inbounds(ctx)
	if err != nil || len(page.Items) != 1 {
		t.Fatal("failed inbound survived rollback", err)
	}
	view, err := s.Inbound(ctx, existing.InboundID)
	if err != nil || view.Health != "healthy" {
		t.Fatal("existing server was disturbed", err)
	}
	response, err = apiServer.Client().Get(apiServer.URL + "/api/v1/system")
	if err != nil {
		t.Fatal("API lost during UDP conflict", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("API lost during UDP conflict", response.StatusCode)
	}
	probe, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatal("failed candidate retained partial TCP socket", err)
	}
	_ = probe.Close()
	t.Logf("external_udp_owner=%p address=%s domain=%s errno=%d revision_before=%v revision_after=%v pending=0 existing_server=healthy api=200 failed_inbound=absent tcp_rollback=PASS", owner, address, domain.Code, syscall.EADDRINUSE, before.Revision, after.Revision)
	_ = owner.Close()
	plan, err = s.PlanSnell(ctx, draft)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := s.ApplySnell(ctx, application.ApplyRequest{Document: draft, Digest: plan.Digest, Revision: plan.Revision})
	if err != nil {
		t.Fatal("normal supported apply after releasing control socket failed", err)
	}
	view, err = s.Inbound(ctx, recovered.InboundID)
	if err != nil || view.Health != "healthy" {
		t.Fatal("recovered listener unhealthy", err)
	}
}
