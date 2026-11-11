package testkit

import "github.com/ike-sh/Splicore/internal/splicore/privatefs"

func privateTLSDirectory(path string) error { return privatefs.EnsureDirectory(path) }
