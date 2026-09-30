package transport

import (
	"errors"
	"net/url"
	"os"
	"strconv"
	"syscall"
)

func capabilityPath(cursor string, limit int) string {
	q := url.Values{}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	if limit != 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	return "/api/v1/capabilities?" + q.Encode()
}

func daemonAbsent(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) || platformAbsent(err)
}
