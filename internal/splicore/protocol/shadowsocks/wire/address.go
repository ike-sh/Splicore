package wire

import (
	"bytes"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/address"
	"io"
)

func Address(e access.Endpoint) ([]byte, error) {
	if e.Validate() != nil {
		return nil, ErrFrame
	}
	b, err := address.MarshalSOCKS(e)
	if err != nil {
		return nil, ErrFrame
	}
	return b, nil
}
func ReadAddress(r io.Reader) (access.Endpoint, error) {
	e, err := address.ReadSOCKS(r)
	if err != nil || e.Validate() != nil {
		return access.Endpoint{}, ErrFrame
	}
	return e, nil
}
func splitAddress(b []byte) (access.Endpoint, []byte, error) {
	r := bytes.NewReader(b)
	e, err := ReadAddress(r)
	if err != nil {
		return e, nil, err
	}
	return e, b[len(b)-r.Len():], nil
}
