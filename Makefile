NAME := splicore
TAGS ?= with_quic,with_utls,with_gvisor
GOOS ?= $(shell go env GOHOSTOS)
GOARCH ?= $(shell go env GOHOSTARCH)
EXT := $(if $(filter windows,$(GOOS)),.exe,)
OUTPUT ?= build/$(GOOS)-$(GOARCH)/$(NAME)$(EXT)

.PHONY: build test vet race verify-runtime build-matrix clean

build:
	GOOS="$(GOOS)" GOARCH="$(GOARCH)" SPLICORE_OUTPUT="$(abspath $(OUTPUT))" SPLICORE_BUILD_TAGS="$(TAGS)" bash scripts/splicore-build.sh

test:
	CGO_ENABLED=0 go test -count=1 -timeout=1200s -tags "$(TAGS)" ./...

vet:
	CGO_ENABLED=0 go vet -tags "$(TAGS)" ./...

race:
	go test -race -count=1 -timeout=1200s -tags "$(TAGS)" ./...

verify-runtime: build
	SPLICORE_RUNTIME_BINARY="$(abspath $(OUTPUT))" CGO_ENABLED=0 go test -count=1 -timeout=90s -tags "$(TAGS)" -run '^TestRuntimeBinaryTrafficShutdownAndRestart$$' ./cmd/splicore

build-matrix:
	$(MAKE) build GOOS=windows GOARCH=amd64
	$(MAKE) build GOOS=windows GOARCH=arm64
	$(MAKE) build GOOS=linux GOARCH=amd64
	$(MAKE) build GOOS=linux GOARCH=arm64

clean:
	rm -rf -- build
