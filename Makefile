BINARY_NAME=nabu
MODULE=github.com/nabu-tunnel/nabu
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS=-ldflags "-s -w -X $(MODULE)/pkg/version.Version=$(VERSION) -X $(MODULE)/pkg/version.BuildTime=$(BUILD_TIME)"

GOPATH?=$(shell go env GOPATH)
GOBIN?=$(GOPATH)/bin

.PHONY: all build client relay test test-unit test-race lint fmt vet clean tidy

all: build

## Build
build: client relay

client:
	go build $(LDFLAGS) -o bin/nabu-client ./cmd/nabu-client

relay:
	go build $(LDFLAGS) -o bin/nabu-relay ./cmd/nabu-relay

## Cross-compile
build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/nabu-client-linux-amd64 ./cmd/nabu-client
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/nabu-relay-linux-amd64 ./cmd/nabu-relay

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/nabu-client-linux-arm64 ./cmd/nabu-client
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/nabu-relay-linux-arm64 ./cmd/nabu-relay

build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/nabu-client-darwin-arm64 ./cmd/nabu-client

build-windows-amd64:
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/nabu-client-windows-amd64.exe ./cmd/nabu-client

build-all: build-linux-amd64 build-linux-arm64 build-darwin-arm64 build-windows-amd64

## Test
test: test-unit

test-unit:
	go test -v -timeout 60s ./pkg/...

test-race:
	go test -race -timeout 120s ./pkg/...

test-bench:
	go test -bench=. -benchmem -benchtime=3s ./pkg/...

test-cover:
	go test -coverprofile=coverage.out ./pkg/...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage raporu: coverage.html"

## Code quality
lint:
	@which golangci-lint > /dev/null || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run ./...

fmt:
	gofmt -w .
	@which goimports > /dev/null 2>&1 && goimports -w . || true

vet:
	go vet ./...

## Deps
tidy:
	go mod tidy

## Dev environment
run-relay:
	go run ./cmd/nabu-relay --config configs/relay-dev.yaml

run-client:
	go run ./cmd/nabu-client --relay 127.0.0.1:8443 --port 1080

## Docker
docker-relay:
	docker build -f deploy/docker/Dockerfile.relay -t nabu-relay:dev .

## Clean
clean:
	rm -rf bin/ coverage.out coverage.html

bin:
	mkdir -p bin
