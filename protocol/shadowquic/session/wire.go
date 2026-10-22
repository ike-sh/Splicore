package session

import (
	"encoding/binary"
	"io"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/address"
)

const (
	connect   = 1
	associate = 3
)

func readCommand(r io.Reader) (byte, access.Endpoint, error) {
	var cmd [1]byte
	if _, err := io.ReadFull(r, cmd[:]); err != nil {
		return 0, access.Endpoint{}, err
	}
	if cmd[0] != connect && cmd[0] != associate {
		return 0, access.Endpoint{}, ErrProtocol
	}
	dst, err := address.ReadSOCKS(r)
	if err != nil || cmd[0] == connect && dst.Validate() != nil {
		return 0, access.Endpoint{}, ErrProtocol
	}
	return cmd[0], dst, nil
}

func command(cmd byte, dst access.Endpoint) ([]byte, error) {
	if cmd != connect && cmd != associate || cmd == connect && dst.Validate() != nil {
		return nil, ErrProtocol
	}
	b, err := address.MarshalSOCKS(dst)
	if err != nil {
		return nil, ErrProtocol
	}
	return append([]byte{cmd}, b...), nil
}

func readMapping(r io.Reader) (access.Endpoint, uint16, error) {
	dst, err := address.ReadSOCKS(r)
	if err != nil || dst.Validate() != nil {
		return access.Endpoint{}, 0, ErrProtocol
	}
	var id [2]byte
	if _, err := io.ReadFull(r, id[:]); err != nil {
		return access.Endpoint{}, 0, err
	}
	return dst, binary.BigEndian.Uint16(id[:]), nil
}

func mapping(dst access.Endpoint, id uint16) ([]byte, error) {
	if dst.Validate() != nil {
		return nil, ErrProtocol
	}
	b, err := address.MarshalSOCKS(dst)
	if err != nil {
		return nil, ErrProtocol
	}
	return binary.BigEndian.AppendUint16(b, id), nil
}
