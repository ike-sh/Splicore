package backend

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"golang.org/x/net/http/httpguts"
	"io"
	"net/http"
	"strings"
)

var ErrProtocol = errors.New("invalid Naive CONNECT message")
var ErrBusy = errors.New("Naive tunnel capacity reached")

const MaxHeaders = 32 << 10

func HeaderPadding(response bool) (string, error) {
	low, high := 16, 32
	if response {
		low, high = 30, 62
	}
	// Rejection sampling gives a uniform range without modulo bias.
	span := high - low + 1
	limit := 256 - 256%span
	var b [1]byte
	for {
		if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
			return "", err
		}
		if int(b[0]) < limit {
			break
		}
	}
	n := low + int(b[0])%span
	raw := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	const symbols = "!#$%&'()*+,-./:;<=>?@[]^_`{|}~"
	for i := range raw {
		raw[i] = symbols[int(raw[i])%len(symbols)]
	}
	return string(raw), nil
}
func ValidateHeaders(headers http.Header) error {
	if len(headers) > 32 {
		return ErrProtocol
	}
	size := 0
	seen := map[string]bool{}
	for name, values := range headers {
		key := strings.ToLower(name)
		if !httpguts.ValidHeaderFieldName(name) || seen[key] || len(values) != 1 {
			return ErrProtocol
		}
		seen[key] = true
		switch key {
		case "proxy-authorization", "proxy-authenticate", "padding", "padding-type-request", "padding-type-reply", "fastopen", "host", "content-length", "transfer-encoding", "connection", "proxy-connection", "upgrade", "keep-alive", "te", "trailer", "accept-encoding":
			return ErrProtocol
		}
		for _, value := range values {
			if !httpguts.ValidHeaderFieldValue(value) || strings.ContainsAny(value, "\r\n\x00") {
				return ErrProtocol
			}
			size += len(name) + len(value)
		}
	}
	if size > 8192 {
		return ErrProtocol
	}
	return nil
}
func Authorization(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}
func paddingOffered(h http.Header) (bool, error) {
	values := h.Values("Padding")
	if len(values) > 1 {
		return false, ErrProtocol
	}
	return len(values) == 1, nil
}
