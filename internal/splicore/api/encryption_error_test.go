package api

import (
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEncryptionValidationErrorsRedactCallerMaterial(t *testing.T) {
	for _, message := range []string{"invalid VLESS encryption configuration", "synthetic-private-key", "invalid VLESS encryption configuration" + " synthetic-private-key"} {
		w := httptest.NewRecorder()
		writeError(w, identity.Err(identity.Invalid, message))
		var problem Problem
		if json.Unmarshal(w.Body.Bytes(), &problem) != nil || w.Code != 400 {
			t.Fatal("invalid validation response")
		}
		if strings.Contains(problem.Message, "synthetic-private-key") {
			t.Fatal("untrusted error disclosed")
		}
	}
}
