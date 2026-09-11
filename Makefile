BINARY_NAME=proxy-gateway
MIGRATE_BINARY=migrate
MIGRATE_INBOUNDS_BINARY=migrate-inbounds
VALIDATE_INBOUNDS_BINARY=validate-inbounds
VERSION?=0.1.0
BUILD_DIR=build
GO=go

.PHONY: all build clean test lint

all: build

build:
	mkdir -p $(BUILD_DIR)
	$(GO) build -ldflags "-s -w -X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/gateway
	$(GO) build -ldflags "-s -w" -o $(BUILD_DIR)/$(MIGRATE_BINARY) ./cmd/migrate
	$(GO) build -ldflags "-s -w" -o $(BUILD_DIR)/$(MIGRATE_INBOUNDS_BINARY) ./cmd/migrate-inbounds
	$(GO) build -ldflags "-s -w" -o $(BUILD_DIR)/$(VALIDATE_INBOUNDS_BINARY) ./cmd/validate-inbounds

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
