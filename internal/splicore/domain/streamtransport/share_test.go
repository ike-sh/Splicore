package streamtransport

import (
	"net/url"
	"testing"
)

func FuzzShareTransportFields(f *testing.F) {
	for _, s := range []string{"type=ws&path=%2Ftest&host=owned.test", "type=httpupgrade&path=%2Fup", "type=grpc&serviceName=Owned", "type=xhttp", "type=ws&type=grpc"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			return
		}
		q, e := url.ParseQuery(s)
		if e != nil {
			return
		}
		c, e := Query(q)
		if e == nil {
			if c.Validate() != nil {
				t.Fatal("accepted invalid config")
			}
			out := url.Values{}
			if e = c.PutQuery(out); e == nil {
				next, e := Query(out)
				if e != nil || next.Type() != c.Type() {
					t.Fatal("transport discriminator not retained")
				}
			}
		}
	})
}
