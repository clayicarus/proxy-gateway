BINARY_NAME=hy2-gateway
VERSION?=0.1.0
BUILD_DIR=build
GO=go

.PHONY: all build clean test lint

all: build

build:
	$(GO) build -ldflags "-s -w -X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/gateway

clean:
	rm -rf $(BUILD_DIR)

test:
	$(GO) test -v ./...

lint:
	golangci-lint run ./...

run: build
	$(BUILD_DIR)/$(BINARY_NAME) -c configs/gateway.yaml

docker:
	docker build -t $(BINARY_NAME):$(VERSION) .
