package application

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
)

func (s *Service) digest(b []byte, r identity.Revision) string {
	var compact bytes.Buffer
	_ = json.Compact(&compact, b)
	b = compact.Bytes()
	h := hmac.New(sha256.New, s.runtime.key[:])
	_, _ = h.Write(b)
	_, _ = fmt.Fprintf(h, "/%d", r)
	return hex.EncodeToString(h.Sum(nil))
}
