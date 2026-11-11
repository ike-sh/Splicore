package identity

import (
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"
)

func TestIDAndRevision(t *testing.T) {
	seen := map[ID]bool{}
	for range 1000 {
		id, err := NewID()
		if err != nil || id.Validate() != nil || seen[id] {
			t.Fatalf("invalid or duplicate random ID: %v", err)
		}
		seen[id] = true
	}
	for _, s := range []string{"example.com", "192.0.2.1", "00000000-0000-0000-0000-000000000000", "ABCDEF12-1234-4234-8234-123456789abc"} {
		if _, err := ParseID(s); err == nil {
			t.Fatal("invalid ID accepted")
		}
	}
	if _, err := Revision(math.MaxInt64).Next(); err == nil {
		t.Fatal("overflow accepted")
	}
	b, err := json.Marshal(Revision(math.MaxInt64))
	if err != nil || string(b) != `"9223372036854775807"` {
		t.Fatal("revision precision lost")
	}
	for _, s := range []string{`1`, `"-1"`, `"1.5"`, `"9223372036854775808"`} {
		var r Revision
		if json.Unmarshal([]byte(s), &r) == nil {
			t.Fatal("invalid revision accepted")
		}
	}
	var e *Error
	if !errors.As(RevisionConflict(3), &e) || e.Code != Conflict || e.Current != 3 {
		t.Fatal("conflict is not typed")
	}
}

func TestUTCMetadataAndTransaction(t *testing.T) {
	now := time.Now()
	stamp := NewStamp(now)
	if stamp.Validate() != nil || stamp.CreatedAt.Location() != time.UTC {
		t.Fatal("timestamp not UTC")
	}
	if (Metadata{"api_token": "dummy"}).Validate() == nil {
		t.Fatal("secret metadata key accepted")
	}
	if (Metadata{"notes": "line\nbreak"}).Validate() == nil {
		t.Fatal("control characters accepted")
	}
	id, _ := NewID()
	op := Transaction{ID: id, State: Pending, CreatedAt: now.UTC()}
	if op.Finish(Committed, now.Add(time.Second), "") != nil || op.Finish(Failed, now.Add(2*time.Second), Invalid) == nil {
		t.Fatal("illegal transaction transition")
	}
}

func FuzzParseID(f *testing.F) {
	f.Add("00000000-0000-4000-8000-000000000001")
	f.Add("example.com")
	f.Fuzz(func(t *testing.T, s string) {
		id, err := ParseID(s)
		if err == nil && (string(id) != s || id.Validate() != nil) {
			t.Fatal("ID roundtrip")
		}
	})
}
