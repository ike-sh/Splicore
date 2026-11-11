package application_test

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/storage/sqlite"
)

// Linux supports stopped-service maintenance backup. Other platforms must
// reject it without output; their persistence checks reopen the original DB.
func persistedDatabaseFixture(t *testing.T, ctx context.Context, source, destination string) string {
	t.Helper()
	schema, err := sqlite.MaintenanceBackup(ctx, source, destination)
	if runtime.GOOS != "linux" {
		if err == nil || !strings.Contains(err.Error(), "requires Linux") || schema != 0 {
			t.Fatalf("unsupported maintenance did not reject: schema=%d err=%v", schema, err)
		}
		if _, err := os.Lstat(destination); !os.IsNotExist(err) {
			t.Fatal("unsupported maintenance created an output", err)
		}
		t.Log("Linux maintenance backup rejected; validate committed state by reopening the source")
		return source
	}
	if err != nil || schema != 8 {
		t.Fatal("maintenance backup", schema, err)
	}
	return destination
}
