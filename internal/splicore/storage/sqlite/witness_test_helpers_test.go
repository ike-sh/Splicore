package sqlite

import (
	"os"
	"testing"
)

func copyWitnessForTest(t *testing.T, sourceDatabase, destinationDatabase string) {
	t.Helper()
	data, err := os.ReadFile(sourceDatabase + witnessSuffix)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(destinationDatabase+witnessSuffix, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// rebaselineFixtureForTest explicitly acknowledges direct SQL fixture setup.
// Production callers have no equivalent shortcut; the exported stopped-store
// EstablishCommitWitness path only creates a missing legacy baseline.
func rebaselineFixtureForTest(t *testing.T, s *Store) {
	t.Helper()
	state, err := databaseWitnessState(t.Context(), s.db, true)
	if err != nil {
		t.Fatal(err)
	}
	next := initialWitness(state, witnessLineageLegacy, witnessKindBaseline)
	if err = persistCommitWitness(s.path, &s.witness, next); err != nil {
		t.Fatal(err)
	}
	s.witness = next
}
