# NoSwiper Makefile
# Simple build and run commands

BINARY_NAME = noswiper-agent
OUT_DIR = out

.PHONY: all build release clean monitor enforce test lint help

# Default target
all: build

help: ## Show this help
	@echo "NoSwiper Makefile"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build     - Build debug binary"
	@echo "  release   - Build release binary"
	@echo "  monitor   - Build and run in monitor mode (requires sudo)"
	@echo "  enforce   - Build and run in enforce mode (requires sudo)"
	@echo "  test      - Run tests"
	@echo "  lint      - Run linters"
	@echo "  clean     - Clean build artifacts"

build: ## Build debug binary
	cargo build

release: $(OUT_DIR) ## Build release binary
	cargo build --release
	cp target/release/$(BINARY_NAME) $(OUT_DIR)/
	@echo "Release binary: $(OUT_DIR)/$(BINARY_NAME)"

monitor: build ## Build and run in monitor mode
	@echo "Starting in monitor mode (requires sudo)..."
	sudo target/debug/$(BINARY_NAME) --monitor

enforce: build ## Build and run in enforce mode
	@echo "Starting in enforce mode (requires sudo)..."
	sudo target/debug/$(BINARY_NAME) --enforce

test: ## Run tests
	cargo test

lint: ## Run linters
	cargo fmt --check
	cargo clippy -- -D warnings

clean: ## Clean build artifacts
	cargo clean
	rm -rf $(OUT_DIR)

$(OUT_DIR):
	mkdir -p $(OUT_DIR)