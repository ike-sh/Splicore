package networkruntime

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func TestUnderlayDNSBootstrapDoTAndHealth(t *testing.T) {
	x := testkit.NewUnderlay(t)
	ctx := context.Background()
	l, err := x.Factory.Begin(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, kind := range []string{"udp", "tcp", "dot"} {
		t.Run(kind, func(t *testing.T) {
			var count atomic.Int64
			handler := answerHandler(&count, "127.0.0.1")
			var tlsConfig *tls.Config
			material := testkit.TLSForName(t, "dns.synthetic.test")
			if kind == "dot" {
				cert, e := tls.LoadX509KeyPair(material.CertificateFile, material.PrivateKeyFile)
				if e != nil {
					t.Fatal(e)
				}
				tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
			}
			var endpoint access.Endpoint
			if kind == "udp" {
				endpoint = dnsFixture(t, "udp", handler, nil)
			} else {
				endpoint = dnsTCPFixture(t, handler, tlsConfig)
			}
			c := dnsConfig(endpoint, kind)
			var bootstrapCount atomic.Int64
			if kind == "dot" {
				c.Servers[0].Endpoint.Host = "dns.synthetic.test"
				c.Servers[0].TLS = access.ClientTLS{Enabled: true, ServerName: material.ServerName, Trust: "explicit_ca", CACertificate: material.CACertificate}
				c.Servers = append(c.Servers, P.DNSServer{ID: testID(2), Name: "bootstrap", Type: "udp", Endpoint: dnsFixture(t, "udp", answerHandler(&bootstrapCount, "127.0.0.1"), nil), Detour: P.Action{Kind: P.Direct}})
				c.DNS.BootstrapServer = testID(2)
			}
			e, err := NewWithUnderlay(x.Factory, l.ID, c, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			r, err := e.Lookup(ctx, "answer.fixture.invalid")
			if err != nil || len(r.Addresses) != 1 {
				t.Fatal(r, err)
			}
			if kind == "dot" && bootstrapCount.Load() == 0 {
				t.Fatal("DoT hostname was not bootstrapped")
			}
			if c.Servers[0].Endpoint.Host == "dns.synthetic.test" && c.Servers[0].TLS.ServerName != material.ServerName {
				t.Fatal("TLS name changed to resolved IP")
			}
			if kind != "dot" {
				if _, err = e.Bootstrap(ctx, "bootstrap.fixture.invalid"); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	system := dnsConfig(access.Endpoint{}, "system")
	e, err := NewWithUnderlay(x.Factory, l.ID, system, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Lookup(ctx, "system.fixture.invalid"); err == nil {
		t.Fatal("unsafe System DNS combination accepted")
	}
	e.Close()
	httpFixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer httpFixture.Close()
	group := testID(8)
	c := P.Config{Groups: []P.PolicyGroup{{ID: group, Name: "health", Type: "url_test", Members: []P.Action{{Kind: P.Direct}}, URLTest: &P.URLTestSettings{Probe: P.Probe{URL: httpFixture.URL, IntervalSeconds: 60, TimeoutSeconds: 2, ExpectedStatus: 204}}}}}
	e, err = NewWithUnderlay(x.Factory, l.ID, c, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.probe(ctx, group, P.Action{Kind: P.Direct})
	if x.Backend.Count(underlay.DNSUpstream) < 3 || x.Backend.Count(underlay.DNSBootstrap) < 2 || x.Backend.Count(underlay.HealthProbe) != 1 {
		t.Fatal("DNS/health socket escaped typed factory")
	}
}
