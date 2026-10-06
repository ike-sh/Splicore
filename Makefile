NAME := splicore
TAGS ?= with_gvisor,with_quic,with_utls
OUTPUT ?= $(NAME)

# Product builds use the preinstalled toolchain. Release packaging and metadata
# are owned by scripts/splicore-package.py and scripts/splicore-build.ps1.
export GOTOOLCHAIN := local

.PHONY: build test race native-test native-race

build:
	go build -trimpath -tags "$(TAGS)" -o "$(OUTPUT)" ./cmd/splicore

test:
	go test ./...

race:
	go test -race ./...

native-test:
	go test -tags "$(TAGS)" ./...

native-race:
	go test -race -tags "$(TAGS)" ./...
