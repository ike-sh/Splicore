package sqlite

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
)

func persistedDatabaseFixture(t *testing.T, ctx context.Context, source, destination string) string {
	t.Helper()
	schema, err := MaintenanceBackup(ctx, source, destination)
	if runtime.GOOS != "linux" {
		if err == nil || schema != 0 || !strings.Contains(err.Error(), "requires Linux") {
			t.Fatal("unsupported maintenance accepted", schema, err)
		}
		if _, err := os.Lstat(destination); !os.IsNotExist(err) {
			t.Fatal("unsupported maintenance created output", err)
		}
		t.Log("maintenance correctly unsupported; reopen committed source")
		return source
	}
	if err != nil || schema != 8 {
		t.Fatal(schema, err)
	}
	return destination
}
