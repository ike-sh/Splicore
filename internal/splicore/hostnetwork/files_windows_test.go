package hostnetwork

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestRecoveryDescriptorBinaryIdentitiesAndStrictGrants(t *testing.T) {
	// A domain-relative Administrator SID may be rendered as LA by Windows.
	// Validate its identity, without requiring a particular SDDL spelling.
	for _, raw := range []string{"S-1-5-21-100-200-300-500", "S-1-5-21-100-200-300-1001"} {
		t.Run(raw, func(t *testing.T) {
			user, err := windows.StringToSid(raw)
			if err != nil {
				t.Fatal(err)
			}
			for _, fixture := range []struct {
				name, descriptor string
				accept           bool
			}{
				{"owner-system", "O:USERD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;USER)", true},
				{"foreign-owner", "O:SYD:P(A;;FA;;;USER)", false},
				{"world-grant", "O:USERD:P(A;;FA;;;USER)(A;;FA;;;WD)", false},
				{"administrator-group", "O:USERD:P(A;;FA;;;USER)(A;;FA;;;BA)", false},
				{"foreign-user", "O:USERD:P(A;;FA;;;S-1-5-21-100-200-300-1002)", false},
				{"partial-rights", "O:USERD:P(A;;FR;;;USER)", false},
				{"deny-ace", "O:USERD:P(D;;FA;;;WD)(A;;FA;;;USER)", false},
				{"empty-dacl", "O:USERD:P", false},
				{"null-dacl", "O:USER", false},
			} {
				t.Run(fixture.name, func(t *testing.T) {
					sd, err := windows.SecurityDescriptorFromString(strings.ReplaceAll(fixture.descriptor, "USER", raw))
					if err != nil {
						t.Fatal(err)
					}
					if err = checkRecoveryDescriptor(sd, user); (err == nil) != fixture.accept {
						t.Fatalf("accept=%v descriptor=%s error=%v", fixture.accept, sd.String(), err)
					}
				})
			}
		})
	}
}
