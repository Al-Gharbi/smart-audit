BINARY     := smart-audit
VERSION    := 1.0.0
BUILD_DIR  := dist
GO         := go
LDFLAGS    := -ldflags "-s -w -X github.com/Al-Gharbi/smart-audit/cmd.Version=$(VERSION)"

.PHONY: all build test lint clean install release docker help

all: build

## build: compile binary for current OS/arch
build:
	@echo "→ Building $(BINARY) v$(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) ./
	@echo "✓ $(BUILD_DIR)/$(BINARY)"

## test: run all unit tests
test:
	$(GO) test ./... -v -race -cover

## lint: run go vet + staticcheck
lint:
	$(GO) vet ./...
	@which staticcheck > /dev/null 2>&1 && staticcheck ./... || echo "[skip] staticcheck not installed"

## install: install binary to GOPATH/bin
install:
	$(GO) install $(LDFLAGS) ./
	@echo "✓ Installed to $$($(GO) env GOPATH)/bin/$(BINARY)"

## clean: remove build artifacts
clean:
	rm -rf $(BUILD_DIR)
	@echo "✓ Cleaned"

## release: cross-compile for Linux, macOS, Windows
release:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux   GOARCH=amd64  $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64   ./
	GOOS=linux   GOARCH=arm64  $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-arm64   ./
	GOOS=darwin  GOARCH=amd64  $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-amd64  ./
	GOOS=darwin  GOARCH=arm64  $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-arm64  ./
	GOOS=windows GOARCH=amd64  $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe ./
	@echo "✓ Cross-compiled binaries in $(BUILD_DIR)/"

## docker: build Docker image
docker:
	docker build -t al-gharbi/smart-audit:$(VERSION) -t al-gharbi/smart-audit:latest .
	@echo "✓ Docker image built"

## help: show this help
help:
	@grep -E '^## ' Makefile | sed 's/## /  /'
