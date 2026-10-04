package application_test

import (
	"context"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"path/filepath"
	"reflect"
	"testing"
)

func FuzzProviderDiff(f *testing.F) {
	f.Add("canonical", `{"schema_version":1,"nodes":[]}`)
	f.Add("uri", "unknown://SECRET@host")
	f.Fuzz(func(t *testing.T, format, content string) {
		if len(content) > 65536 {
			return
		}
		s, store := setupSnell(t, filepath.Join(t.TempDir(), "state", "state.db"), nil)
		defer stop(t, s, store)
		enableClient(t, s)
		before, e := s.ClientStatus(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		_, _ = s.PreviewManagement(context.Background(), application.ManagementRequest{Operation: "import", InputFormat: format, Content: content})
		after, e := s.ClientStatus(context.Background())
		if e != nil || !reflect.DeepEqual(before.State, after.State) {
			t.Fatal("preview mutated authority", e)
		}
	})
}
