// Package wire encodes the public AnyTLS authentication and session formats.
package wire

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	Waste byte = iota
	Open
	Data
	Finish
	Settings
	Alert
	PaddingUpdate
	OpenResult
	Heartbeat
	HeartbeatReply
	ServerSettings
)

const HeaderSize = 7
const MaxPayload = 65535
const MaxSettings = 8192
const MaxAlert = 1024

var ErrProtocol = errors.New("invalid AnyTLS protocol input")

type AuthKey [32]byte

func PasswordKey(password string) AuthKey { return sha256.Sum256([]byte(password)) }

// Match visits the bounded identity snapshot without comparing secret strings.
func Match(key AuthKey, users map[AuthKey]string) (string, bool) {
	var id string
	matched := 0
	for candidate, value := range users {
		if subtle.ConstantTimeCompare(key[:], candidate[:]) == 1 {
			id = value
			matched++
		}
	}
	return id, matched == 1
}

func Authentication(key AuthKey, padding []byte) ([]byte, error) {
	if len(padding) > MaxPayload {
		return nil, ErrProtocol
	}
	b := make([]byte, 34+len(padding))
	copy(b, key[:])
	binary.BigEndian.PutUint16(b[32:34], uint16(len(padding)))
	copy(b[34:], padding)
	return b, nil
}

func ReadAuthentication(r io.Reader) (AuthKey, error) {
	var key AuthKey
	var header [34]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return key, err
	}
	n := int64(binary.BigEndian.Uint16(header[32:]))
	if _, err := io.CopyN(io.Discard, r, n); err != nil {
		return key, err
	}
	copy(key[:], header[:32])
	clear(header[:])
	return key, nil
}

type Frame struct {
	Command byte
	Stream  uint32
	Payload []byte
}

func AppendFrame(b []byte, f Frame) ([]byte, error) {
	if len(f.Payload) > MaxPayload || f.Command > ServerSettings {
		return b, ErrProtocol
	}
	b = append(b, f.Command)
	b = binary.BigEndian.AppendUint32(b, f.Stream)
	b = binary.BigEndian.AppendUint16(b, uint16(len(f.Payload)))
	return append(b, f.Payload...), nil
}

func ReadFrame(r io.Reader) (Frame, error) {
	var f Frame
	var header [HeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return f, err
	}
	f.Command, f.Stream = header[0], binary.BigEndian.Uint32(header[1:5])
	n := int(binary.BigEndian.Uint16(header[5:]))
	if f.Command > ServerSettings {
		return f, ErrProtocol
	}
	if (f.Command == Settings || f.Command == ServerSettings || f.Command == PaddingUpdate) && n > MaxSettings || (f.Command == Alert || f.Command == OpenResult) && n > MaxAlert {
		return f, ErrProtocol
	}
	if (f.Command == Open || f.Command == Finish || f.Command == Heartbeat || f.Command == HeartbeatReply) && n != 0 {
		return f, ErrProtocol
	}
	f.Payload = make([]byte, n)
	_, err := io.ReadFull(r, f.Payload)
	return f, err
}

// ParseSettings accepts unknown optional keys but rejects ambiguous duplicate keys.
func ParseSettings(data []byte) (map[string]string, error) {
	if len(data) == 0 || len(data) > MaxSettings || !utf8.Valid(data) || strings.ContainsAny(string(data), "\x00\r") {
		return nil, ErrProtocol
	}
	values := make(map[string]string)
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) > 32 {
		return nil, ErrProtocol
	}
	for _, line := range lines {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" || len(key) > 64 || len(value) > 4096 || strings.TrimSpace(key) != key {
			return nil, ErrProtocol
		}
		if _, duplicate := values[key]; duplicate {
			return nil, ErrProtocol
		}
		values[key] = value
	}
	version := values["v"]
	if version == "" {
		return nil, ErrProtocol
	}
	for _, c := range version {
		if c < '0' || c > '9' {
			return nil, ErrProtocol
		}
	}
	v, err := strconv.ParseUint(version, 10, 16)
	if err != nil || v == 0 {
		return nil, ErrProtocol
	}
	if hash, present := values["padding-md5"]; present {
		if len(hash) != 32 {
			return nil, ErrProtocol
		}
		for _, c := range hash {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return nil, ErrProtocol
			}
		}
	}
	return values, nil
}

func Version(values map[string]string) int {
	v, _ := strconv.ParseUint(values["v"], 10, 16)
	if v >= 2 {
		return 2
	}
	return 1
}

// WriteAll treats a non-progressing writer as an error rather than looping.
func WriteAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}
