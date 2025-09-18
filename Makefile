# NoSwiper Makefile
# Build, test, and install the NoSwiper credential protection daemon

# Variables
BINARY_NAME = noswiper-agent
CARGO = RUSTFLAGS="-D warnings" cargo
RUSTFMT = rustfmt
CLIPPY = clippy
OUT_DIR = out
INSTALL_DIR = /usr/local/bin
VERSION = $(shell grep version Cargo.toml | head -1 | cut -d'"' -f2)

# Platform detection (portable for BSD/GNU make)
UNAME_S = $(shell uname -s)
UNAME_M = $(shell uname -m)

# Default target - build release binary to out/ directory
.DEFAULT_GOAL := release

# Determine target triple and platform using shell commands
TARGET = $(shell \
	if [ "$(UNAME_S)" = "Darwin" ]; then \
		if [ "$(UNAME_M)" = "arm64" ]; then \
			echo "aarch64-apple-darwin"; \
		else \
			echo "x86_64-apple-darwin"; \
		fi; \
	elif [ "$(UNAME_S)" = "Linux" ]; then \
		if [ "$(UNAME_M)" = "aarch64" ]; then \
			echo "aarch64-unknown-linux-gnu"; \
		else \
			echo "x86_64-unknown-linux-gnu"; \
		fi; \
	else \
		echo "unknown-target"; \
	fi)

PLATFORM = $(shell \
	if [ "$(UNAME_S)" = "Darwin" ]; then \
		echo "macos"; \
	elif [ "$(UNAME_S)" = "Linux" ]; then \
		echo "linux"; \
	else \
		echo "unknown"; \
	fi)

# Build output paths
RELEASE_BINARY = target/release/$(BINARY_NAME)
DEBUG_BINARY = target/debug/$(BINARY_NAME)
OUT_BINARY = $(OUT_DIR)/$(BINARY_NAME)-$(PLATFORM)-$(UNAME_M)

# Phony targets
.PHONY: all help lint fmt check test build release clean install uninstall monitor run-monitor run-interactive run-enforce

## Help
help: ## Show this help message
	@echo "NoSwiper Makefile"
	@echo "================="
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Platform: $(PLATFORM) ($(TARGET))"
	@echo "Version:  $(VERSION)"

## Linting
lint: ## Run all linters (fmt-check, clippy, check)
	@echo "Running linters..."
	@$(MAKE) fmt-check
	@$(MAKE) clippy
	@$(MAKE) check
	@echo "✓ All lints passed"

fmt: ## Format code using rustfmt
	@echo "Formatting code..."
	@$(CARGO) fmt

fmt-check: ## Check code formatting without modifying files
	@echo "Checking code formatting..."
	@$(CARGO) fmt -- --check || (echo "❌ Code needs formatting. Run 'make fmt'" && exit 1)
	@echo "✓ Code formatting is correct"

clippy: ## Run clippy linter
	@echo "Running clippy..."
	@$(CARGO) clippy -- -D warnings || (echo "❌ Clippy found issues" && exit 1)
	@echo "✓ Clippy checks passed"

check: ## Type-check the code without building
	@echo "Type-checking code..."
	@$(CARGO) check
	@echo "✓ Type check passed"

## Testing
test: ## Run all tests
	@echo "Running tests..."
	@$(CARGO) test
	@echo "✓ All tests passed"

test-verbose: ## Run tests with verbose output
	@$(CARGO) test -- --nocapture

## Building
build: ## Build debug binary
	@echo "Building debug binary..."
	@$(CARGO) build
	@echo "✓ Debug build complete: $(DEBUG_BINARY)"

release: $(OUT_DIR) ## Build release binary and copy to out/
	@echo "Building release binary for $(PLATFORM) ($(TARGET))..."
	@$(CARGO) build --release --target $(TARGET)
	@cp target/$(TARGET)/release/$(BINARY_NAME) $(OUT_BINARY)
	@chmod +x $(OUT_BINARY)
	@echo "✓ Release binary built: $(OUT_BINARY)"
	@ls -lh $(OUT_BINARY)

release-native: $(OUT_DIR) ## Build release binary for native platform
	@echo "Building native release binary..."
	@$(CARGO) build --release
	@cp $(RELEASE_BINARY) $(OUT_DIR)/$(BINARY_NAME)
	@chmod +x $(OUT_DIR)/$(BINARY_NAME)
	@echo "✓ Native release binary built: $(OUT_DIR)/$(BINARY_NAME)"
	@ls -lh $(OUT_DIR)/$(BINARY_NAME)

## Cross-compilation targets
linux-x64: $(OUT_DIR) ## Build for Linux x86_64
	@echo "Building for Linux x86_64..."
	@rustup target add x86_64-unknown-linux-gnu 2>/dev/null || true
	@cross build --release --target x86_64-unknown-linux-gnu || \
		(echo "Install cross: cargo install cross" && exit 1)
	@cp target/x86_64-unknown-linux-gnu/release/$(BINARY_NAME) $(OUT_DIR)/$(BINARY_NAME)-linux-x64
	@chmod +x $(OUT_DIR)/$(BINARY_NAME)-linux-x64
	@echo "✓ Linux x64 binary built: $(OUT_DIR)/$(BINARY_NAME)-linux-x64"

linux-arm64: $(OUT_DIR) ## Build for Linux ARM64
	@echo "Building for Linux ARM64..."
	@rustup target add aarch64-unknown-linux-gnu 2>/dev/null || true
	@cross build --release --target aarch64-unknown-linux-gnu || \
		(echo "Install cross: cargo install cross" && exit 1)
	@cp target/aarch64-unknown-linux-gnu/release/$(BINARY_NAME) $(OUT_DIR)/$(BINARY_NAME)-linux-arm64
	@chmod +x $(OUT_DIR)/$(BINARY_NAME)-linux-arm64
	@echo "✓ Linux ARM64 binary built: $(OUT_DIR)/$(BINARY_NAME)-linux-arm64"

macos-x64: $(OUT_DIR) ## Build for macOS x86_64
	@echo "Building for macOS x86_64..."
	@rustup target add x86_64-apple-darwin 2>/dev/null || true
	@$(CARGO) build --release --target x86_64-apple-darwin
	@cp target/x86_64-apple-darwin/release/$(BINARY_NAME) $(OUT_DIR)/$(BINARY_NAME)-macos-x64
	@chmod +x $(OUT_DIR)/$(BINARY_NAME)-macos-x64
	@echo "✓ macOS x64 binary built: $(OUT_DIR)/$(BINARY_NAME)-macos-x64"

macos-arm64: $(OUT_DIR) ## Build for macOS ARM64 (Apple Silicon)
	@echo "Building for macOS ARM64..."
	@rustup target add aarch64-apple-darwin 2>/dev/null || true
	@$(CARGO) build --release --target aarch64-apple-darwin
	@cp target/aarch64-apple-darwin/release/$(BINARY_NAME) $(OUT_DIR)/$(BINARY_NAME)-macos-arm64
	@chmod +x $(OUT_DIR)/$(BINARY_NAME)-macos-arm64
	@echo "✓ macOS ARM64 binary built: $(OUT_DIR)/$(BINARY_NAME)-macos-arm64"

all-platforms: linux-x64 linux-arm64 macos-x64 macos-arm64 ## Build for all supported platforms
	@echo "✓ All platform binaries built"
	@ls -lh $(OUT_DIR)/

## Installation
install: release ## Install the binary to system (requires sudo)
	@echo "Installing $(BINARY_NAME) to $(INSTALL_DIR)..."
	@sudo cp $(OUT_BINARY) $(INSTALL_DIR)/$(BINARY_NAME)
	@sudo chmod +x $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "✓ Installed to $(INSTALL_DIR)/$(BINARY_NAME)"
	@echo ""
	@echo "Run with: sudo $(BINARY_NAME) --interactive"

uninstall: ## Uninstall the binary from system (requires sudo)
	@echo "Removing $(BINARY_NAME) from $(INSTALL_DIR)..."
	@sudo rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "✓ Uninstalled"

## Running
monitor: release ## Build release and run in monitor mode
	@echo "Starting release binary in monitor mode..."
	@sudo $(OUT_BINARY) --monitor

run-monitor: build ## Run in monitor mode (log only)
	@echo "Starting in monitor mode..."
	@sudo $(DEBUG_BINARY) --monitor

run-interactive: build ## Run in interactive mode
	@echo "Starting in interactive mode..."
	@sudo $(DEBUG_BINARY) --interactive

run-enforce: build ## Run in enforce mode (block access)
	@echo "Starting in enforce mode..."
	@sudo $(DEBUG_BINARY) --enforce

## Utility
clean: ## Clean build artifacts and output directory
	@echo "Cleaning build artifacts..."
	@$(CARGO) clean
	@rm -rf $(OUT_DIR)
	@echo "✓ Cleaned"

$(OUT_DIR): ## Create output directory
	@mkdir -p $(OUT_DIR)

show-config: build ## Show default configuration
	@$(DEBUG_BINARY) --show-config

version: ## Show version information
	@echo "NoSwiper version $(VERSION)"
	@echo "Platform: $(PLATFORM) ($(TARGET))"
	@$(CARGO) --version
	@rustc --version

deps: ## Install development dependencies
	@echo "Installing development dependencies..."
	@rustup component add rustfmt clippy 2>/dev/null || true
	@command -v cross >/dev/null 2>&1 || cargo install cross
	@echo "✓ Dependencies installed"

## Documentation
docs: ## Generate and open documentation
	@$(CARGO) doc --open

## Security audit
audit: ## Run security audit on dependencies
	@command -v cargo-audit >/dev/null 2>&1 || cargo install cargo-audit
	@cargo audit

## Benchmarking
bench: ## Run benchmarks
	@$(CARGO) bench

## Distribution
dist: release ## Create distribution package
	@echo "Creating distribution package..."
	@mkdir -p dist
	@cp $(OUT_BINARY) dist/
	@cp README.md dist/
	@cp LICENSE* dist/ 2>/dev/null || true
	@tar -czf dist/$(BINARY_NAME)-$(VERSION)-$(PLATFORM)-$(UNAME_M).tar.gz -C dist .
	@echo "✓ Distribution package created: dist/$(BINARY_NAME)-$(VERSION)-$(PLATFORM)-$(UNAME_M).tar.gz"

## CI/CD helpers
ci: lint test release ## Run CI pipeline (lint, test, build release)
	@echo "✓ CI pipeline complete"

pre-commit: fmt lint test ## Run pre-commit checks
	@echo "✓ Pre-commit checks passed"

# Development helpers
watch: ## Watch for changes and rebuild
	@command -v cargo-watch >/dev/null 2>&1 || cargo install cargo-watch
	@cargo watch -c -x build

todo: ## Show TODO items in code
	@grep -r "TODO\|FIXME\|HACK\|NOTE" src/ --exclude-dir=target || echo "No TODOs found"

loc: ## Count lines of code
	@echo "Lines of code:"
	@find src -name "*.rs" | xargs wc -l | tail -1