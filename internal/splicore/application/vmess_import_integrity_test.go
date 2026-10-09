//go:build with_quic && with_utls

package application_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/api"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/provider"
	"github.com/ike-sh/Splicore/internal/splicore/nodeimport"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
)

const fix1ImportUUID = "11111111-1111-1111-1111-111111111111"

func fix1Batch(format string, order []int) string {
	var items []any
	var uris []string
	var candidates []nodeimport.Candidate
	for _, index := range order {
		uri := map[string]any{"v": "2", "ps": "fix1 synthetic", "add": "localhost", "port": 443, "id": fix1ImportUUID, "aid": 0, "scy": "auto", "net": "tcp"}
		n := map[string]any{"type": "vmess", "server": "localhost", "uuid": fix1ImportUUID}
		alter, security := "alter_id", "security"
		if format == "mihomo" {
			n["name"] = "fix1 synthetic"
			n["port"] = 443
			alter, security = "alterId", "cipher"
		} else {
			n["tag"] = "fix1 synthetic"
			n["server_port"] = 443
		}
		switch index {
		case 1:
			n[alter] = 64
			uri["aid"] = 64
		case 2:
			n["network"] = "xhttp"
			uri["net"] = "xhttp"
		case 3:
			n[security] = "aes-128-cfb"
			uri["scy"] = "aes-128-cfb"
		case 4:
			n["uuid"] = "invalid synthetic credential"
			uri["id"] = "invalid synthetic credential"
		case 5:
			n["tls"] = true
			n["sni"] = "first.test"
			n["servername"] = "second.test"
		}
		raw, _ := json.Marshal(uri)
		if index == 5 {
			raw = append(raw[:len(raw)-1], []byte(`,"aid":64}`)...)
		}
		uris = append(uris, "vmess://"+base64.StdEncoding.EncodeToString(raw))
		items = append(items, n)
		if format == "canonical" {
			base, _ := json.Marshal(map[string]any{"v": "2", "ps": "fix1 synthetic", "add": "localhost", "port": 443, "id": fix1ImportUUID})
			c, _ := nodeimport.ParseURI("vmess://" + base64.StdEncoding.EncodeToString(base))
			switch index {
			case 1:
				c.Node.Options.Data = []byte(`{"alter_id":64}`)
			case 2:
				c.Node.Transport.Kind = "xhttp"
			case 3:
				c.Node.Options.Data = []byte(`{"security":"aes-128-cfb"}`)
			case 4:
				c.Credential.Value = "invalid synthetic credential"
			case 5:
				c.Node.Options.Data = []byte(`{"alter_id":64,"ALTER_ID":0}`)
			}
			candidates = append(candidates, c)
		}
	}
	if format == "uri" || format == "base64" {
		var b bytes.Buffer
		for _, uri := range uris {
			b.WriteString(uri)
			b.WriteByte('\n')
		}
		if format == "base64" {
			return base64.StdEncoding.EncodeToString(b.Bytes())
		}
		return b.String()
	}
	if format == "canonical" {
		b, _ := json.Marshal(nodeimport.Document{Schema: 1, Nodes: candidates})
		return string(b)
	}
	root := "outbounds"
	if format == "mihomo" {
		root = "proxies"
	}
	b, _ := json.Marshal(map[string]any{root: items})
	return string(b)
}
func fix1Codes(p application.ManagementPreview) []string {
	var out []string
	for _, e := range p.Entries {
		if e.Kind == "Invalid" || e.Kind == "Unsupported" {
			out = append(out, e.Change)
		}
	}
	sort.Strings(out)
	return out
}
func fix1AssertCodes(t *testing.T, p application.ManagementPreview, conflict bool) {
	t.Helper()
	want := []string{"unsupported_legacy_vmess", "unsupported_transport", "unsupported_security", "invalid_credential"}
	if conflict {
		want = append(want, "conflicting_field")
	}
	sort.Strings(want)
	if !reflect.DeepEqual(fix1Codes(p), want) {
		t.Fatalf("classification: %+v", p.Entries)
	}
	b, _ := json.Marshal(p)
	for _, secret := range []string{fix1ImportUUID, "invalid synthetic credential", "vmess://"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatal("preview leaked raw secret/input")
		}
	}
}

func TestReviewFix1APIBatchClassification(t *testing.T) {
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	enableVMess(t, s)
	server := httptest.NewServer(api.Handler(s))
	defer server.Close()
	ctl := transport.TestClient(server.Client(), server.URL)
	defer ctl.Close()
	for _, format := range []string{"uri", "base64", "sing-box", "mihomo", "canonical"} {
		conflict := format != "sing-box"
		order := []int{0, 1, 2, 3, 4}
		if conflict {
			order = append(order, 5)
		}
		before, _ := s.ClientStatus(ctx)
		for cycle := range 100 {
			rand.New(rand.NewSource(int64(cycle))).Shuffle(len(order), func(a, b int) { order[a], order[b] = order[b], order[a] })
			p, err := ctl.PreviewManagement(ctx, application.ManagementRequest{Operation: "import", InputFormat: format, Content: fix1Batch(format, order), Mode: "strict"})
			if err != nil {
				t.Fatal(format, err)
			}
			fix1AssertCodes(t, p, conflict)
			if p.Applicable || p.Token != "" {
				t.Fatal("strict mixed input got apply token")
			}
		}
		after, _ := s.ClientStatus(ctx)
		if !reflect.DeepEqual(before.State, after.State) {
			t.Fatal("preview mutated committed DB state")
		}
		if _, err := ctl.ApplyManagement(ctx, application.ManagementApply{Revision: after.State.Revision}); err == nil {
			t.Fatal("strict rejection applied without token")
		}
		t.Logf("format=%s randomized_batches=100 classes_retained=true preview_mutations=0", format)
	}
	// The existing transaction contract rejects strict previews without tokens;
	// lenient apply uses the exact prepared valid candidates and preserves issues.
	p, err := ctl.PreviewManagement(ctx, application.ManagementRequest{Operation: "import", InputFormat: "uri", Content: fix1Batch("uri", []int{0, 1, 2, 3, 4, 5}), Mode: "lenient"})
	if err != nil {
		t.Fatal(err)
	}
	fix1AssertCodes(t, p, true)
	if !p.Applicable {
		t.Fatal("lenient valid candidate rejected")
	}
	if _, err = ctl.ApplyManagement(ctx, application.ManagementApply{Token: p.Token, Revision: p.Revision}); err != nil {
		t.Fatal(err)
	}
	status, _ := s.ClientStatus(ctx)
	if len(status.State.Nodes) != 1 || status.State.Nodes[0].Protocol.Protocol != "vmess" {
		t.Fatal("lenient apply imported rejected candidate")
	}
}

func TestReviewFix1ProviderMixedRollback(t *testing.T) {
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	enableVMess(t, s)
	feed := &managementFeed{}
	feed.set(fix1Batch("uri", []int{0}), "", 0)
	fixture := httptest.NewServer(http.HandlerFunc(feed.serve))
	defer fixture.Close()
	p := managementApply(t, s, application.ManagementRequest{Operation: "provider-upsert", Provider: &provider.Provider{Name: "fix1 synthetic provider", Kind: "proxy", Format: "uri", Mode: "strict", AllowPrivate: true}, Source: &provider.Source{URL: fixture.URL}})
	if _, err := s.RefreshProvider(ctx, p.ProviderID); err != nil {
		t.Fatal(err)
	}
	before, _ := s.ClientStatus(ctx)
	feed.set(fix1Batch("uri", []int{5, 2, 0, 4, 1, 3}), "", 0)
	preview, err := s.PreviewProviderRefresh(ctx, p.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	fix1AssertCodes(t, preview, true)
	if preview.Applicable {
		t.Fatal("strict provider mixed candidates applicable")
	}
	after, _ := s.ClientStatus(ctx)
	if !reflect.DeepEqual(before.State, after.State) {
		t.Fatal("provider preview mutated DB")
	}
	if _, err = s.RefreshProvider(ctx, p.ProviderID); err == nil {
		t.Fatal("strict provider apply accepted invalid candidates")
	}
	after, _ = s.ClientStatus(ctx)
	if !reflect.DeepEqual(before.State.Nodes, after.State.Nodes) || after.State.Management.Providers[0].Generation != before.State.Management.Providers[0].Generation {
		t.Fatal("failed provider refresh did not retain generation")
	}
	feed.set(fix1Batch("uri", []int{0}), "", 0)
	if _, err = s.RefreshProvider(ctx, p.ProviderID); err != nil {
		t.Fatal("valid recovery", err)
	}
	feed.set(fix1Batch("uri", []int{0, 1, 2, 3, 4, 5}), "", 0)
	lenient := managementApply(t, s, application.ManagementRequest{Operation: "provider-upsert", Provider: &provider.Provider{Name: "fix1 lenient provider", Kind: "proxy", Format: "uri", Mode: "lenient", AllowPrivate: true}, Source: &provider.Source{URL: fixture.URL}})
	preview, err = s.PreviewProviderRefresh(ctx, lenient.ProviderID)
	if err != nil || !preview.Applicable {
		t.Fatal("lenient provider preview", err)
	}
	fix1AssertCodes(t, preview, true)
	if _, err = s.RefreshProvider(ctx, lenient.ProviderID); err != nil {
		t.Fatal("lenient provider apply", err)
	}
	if nodes := providerNodes(t, s, lenient.ProviderID); len(nodes) != 1 || nodes[0].Protocol.Protocol != "vmess" {
		t.Fatal("lenient provider imported invalid candidates")
	}
	t.Log("provider preview/apply rollback: rejected classes retained; node/generation unchanged; valid recovery passed")
}
