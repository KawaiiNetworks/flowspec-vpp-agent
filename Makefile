# flowspec-vpp-agent build/test tooling.
#
# The VPP ACL/interface binapi bindings are consumed directly from the
# go.fd.io/govpp module (which ships generated bindings), so this project does
# not run binapigen. If you ever need to regenerate against a specific VPP
# version, see the govpp binapigen docs.

BIN        := flowspec-vpp-agent
PKG        := github.com/kawaiinetworks/flowspec-vpp-agent
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE       ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -s -w \
  -X $(PKG)/internal/version.Version=$(VERSION) \
  -X $(PKG)/internal/version.Commit=$(COMMIT) \
  -X $(PKG)/internal/version.Date=$(DATE)

IMAGE      ?= kawaiinetworks/flowspec-vpp-agent:main

.PHONY: build test vet lint tidy docker run clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BIN) ./cmd/$(BIN)

test:
	go test ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./... || true

tidy:
	go mod tidy

docker:
	docker build -f deploy/Dockerfile \
	  --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) \
	  -t $(IMAGE) .

clean:
	rm -rf bin
