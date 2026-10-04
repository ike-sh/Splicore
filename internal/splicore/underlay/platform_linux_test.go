//go:build linux

package underlay

import "testing"

func TestUnderlayChildSystemResolverBoundary(t *testing.T) {
	for _, config := range []string{"nameserver 192.0.2.53\n", "# comment\nnameserver 2001:db8::53\n"} {
		if err := verifyChildResolver(config); err != nil {
			t.Fatal(err)
		}
	}
	for _, config := range []string{"", "nameserver 127.0.0.53", "nameserver ::1", "nameserver ::ffff:127.0.0.1", "nameserver 0.0.0.0", "nameserver fixture.invalid", "nameserver ff02::1", "nameserver fe80::1%eth0"} {
		if err := verifyChildResolver(config); err == nil {
			t.Fatalf("unsafe resolver accepted: %q", config)
		}
	}
}
