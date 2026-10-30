//go:build with_gvisor

package amneziawgendpoint

import (
	"os"
	"testing"
)

func TestAWGStandardWGUserspaceCompatibility(t *testing.T) {
	old := os.Getenv("SPLICORE_PHASE37_AWG_REFERENCE")
	t.Setenv("SPLICORE_PHASE37_AWG_REFERENCE", os.Getenv("SPLICORE_PHASE34_WG_REFERENCE"))
	t.Setenv("SPLICORE_PHASE37_ORACLE_REVISION", "b3bc704ef0ee21a36298601a9e1e5ff90377ac52")
	TestOfficialAmneziaWGInterop(t)
	_ = old
}
