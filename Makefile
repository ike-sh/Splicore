NAME := splicore
TAGS ?= with_quic,with_utls,with_gvisor
OUTPUT ?= $(NAME)

.PHONY: build

build:
	go build -trimpath -tags "$(TAGS)" -o "$(OUTPUT)" ./cmd/splicore
