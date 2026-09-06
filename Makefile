BINARY_NAME=proxy-gateway
VERSION?=0.1.0
BUILD_DIR=build
GO?=go
export CGO_ENABLED?=1

.PHONY: all build clean test lint race fuzz check run docker

all: build

build:
	mkdir -p "$(BUILD_DIR)"
	$(GO) build -ldflags "-s -w -X main.version=$(VERSION)" -o "$(BUILD_DIR)/$(BINARY_NAME)" ./cmd/gateway

clean:
	rm -rf "$(BUILD_DIR)"

test:
	$(GO) test -count=1 ./...

lint:
	$(GO) vet ./...

race:
	$(GO) test -race -count=1 ./...

fuzz:
	$(GO) test ./internal/trojan -run='^$$' -fuzz=FuzzParseRequest -fuzztime=30s -parallel=2

check: test lint race fuzz build

run: build
	$(BUILD_DIR)/$(BINARY_NAME) -c configs/gateway.yaml

docker:
	docker build -t $(BINARY_NAME):$(VERSION) .
