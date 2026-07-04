# blueeye-agent-go — build, test, cross-compile.
# Single static binary; five release targets.

BIN     := blueeye-agent
PKG     := ./cmd/blueeye-agent
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
DIST    := dist

# CGO off everywhere → truly static binaries.
export CGO_ENABLED=0

.PHONY: all build test vet tidy clean $(DIST) \
        linux-amd64 linux-arm64 windows-amd64 darwin-amd64 darwin-arm64

## build the binary for the host platform
build:
	go build -ldflags "$(LDFLAGS)" -o $(BIN) $(PKG)

## run the full test suite
test:
	go test ./...

## static checks
vet:
	go vet ./...

tidy:
	go mod tidy

## cross-compile all five release targets
all: linux-amd64 linux-arm64 windows-amd64 darwin-amd64 darwin-arm64

$(DIST):
	mkdir -p $(DIST)

linux-amd64: $(DIST)
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BIN)-linux-amd64 $(PKG)

linux-arm64: $(DIST)
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BIN)-linux-arm64 $(PKG)

windows-amd64: $(DIST)
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BIN)-windows-amd64.exe $(PKG)

darwin-amd64: $(DIST)
	GOOS=darwin GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BIN)-darwin-amd64 $(PKG)

darwin-arm64: $(DIST)
	GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BIN)-darwin-arm64 $(PKG)

clean:
	rm -rf $(BIN) $(DIST)
