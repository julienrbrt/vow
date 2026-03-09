SHELL = /bin/bash
.SHELLFLAGS = -o pipefail -c

# Build output directory
BUILD_DIR := dist

# Platforms to build for
PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	linux/arm

.PHONY: help
help: ## Print info about all commands
	@echo "Commands:"
	@echo
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "    \033[01;32m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the vow binary
	go build -o vow ./cmd/vow

.PHONY: build-all
build-all: ## Build binaries for all architectures
	@echo "Building for all architectures..."
	@mkdir -p $(BUILD_DIR)
	@$(foreach platform,$(PLATFORMS), \
		$(eval OS := $(word 1,$(subst /, ,$(platform)))) \
		$(eval ARCH := $(word 2,$(subst /, ,$(platform)))) \
		$(eval OUTPUT := $(BUILD_DIR)/vow-$(OS)-$(ARCH)) \
		echo "Building $(OS)/$(ARCH)..."; \
		GOOS=$(OS) GOARCH=$(ARCH) go build -o $(OUTPUT) ./cmd/vow && \
		echo "  ✓ $(OUTPUT)" || echo "  ✗ Failed: $(OS)/$(ARCH)"; \
	)
	@echo "Done! Binaries are in $(BUILD_DIR)/"

.PHONY: clean
clean: ## Remove built binaries
	rm -rf $(BUILD_DIR) vow

.PHONY: run
run: ## Build and run the PDS
	go run ./cmd/vow run

.PHONY: test
test: ## Run tests
	go clean -testcache && go test -v ./...

.PHONY: lint
lint: ## Verify code style and run static checks
	go vet ./...
	go fix ./...
	test -z "$(shell gofmt -l ./...)"
	golangci-lint run ./... --fix

.PHONY: lint-install
lint-install: ## Install golangci-lint
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

.PHONY: fmt
fmt: ## Format code
	go fmt ./...

.PHONY: check
check: ## Compile everything, checking syntax (does not output binaries)
	go build ./...

.PHONY: docker-build
docker-build: ## Build the Docker image
	docker build -t vow .
