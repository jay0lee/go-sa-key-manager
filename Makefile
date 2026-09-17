BINARY_NAME=gcp-sa-key-manager
VERSION?=$(shell date -u +'%Y.%m.%d.%H%M')
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
BUILD_DATE?=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
LDFLAGS=-ldflags "-s -w -X github.com/jay0lee/go-sa-key-manager/cmd.Version=$(VERSION) -X github.com/jay0lee/go-sa-key-manager/cmd.GitCommit=$(COMMIT) -X github.com/jay0lee/go-sa-key-manager/cmd.BuildDate=$(BUILD_DATE)"
DARWIN_LDFLAGS=-ldflags "-s -w -macos 11.0 -X github.com/jay0lee/go-sa-key-manager/cmd.Version=$(VERSION) -X github.com/jay0lee/go-sa-key-manager/cmd.GitCommit=$(COMMIT) -X github.com/jay0lee/go-sa-key-manager/cmd.BuildDate=$(BUILD_DATE)"

.PHONY: all build test test-live coverage lint clean build-all

all: build

build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY_NAME) main.go

test:
	go test -v -race ./...

test-live: build
	go test -v -tags=live ./test/integration/...

coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

build-all: clean
	@mkdir -p bin
	# macOS Apple Silicon (ARM64 only - Intel x86_64 explicitly excluded)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(DARWIN_LDFLAGS) -o bin/$(BINARY_NAME)-darwin-arm64 main.go
	# Linux x86_64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 main.go
	# Linux ARM64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-arm64 main.go
	# Windows x86_64
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-windows-amd64.exe main.go
	# Windows ARM64
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-windows-arm64.exe main.go
	@echo "Build complete! Artifacts in bin/:"
	@ls -la bin/

clean:
	rm -rf bin coverage.out c.out c.html
