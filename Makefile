# NoSwiper Makefile
# Build and run commands for both agent and UI

AGENT_BINARY = noswiper-agent
UI_BINARY = noswiper-ui
SWIFT_UI_DIR = ui/swift
RUST_UI_DIR = ui/rust
MACOS_APP = NoSwiper.app
OUT_DIR = out

.PHONY: all build agent swift-ui ui release release-agent release-swift-ui clean monitor enforce test lint help run-swift-ui run-ui

# Default target
all: build

help: ## Show this help
	@echo "NoSwiper Makefile"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build            - Build both agent and Swift UI (debug)"
	@echo "  agent            - Build agent only (debug)"
	@echo "  swift-ui         - Build Swift UI for macOS (recommended)"
	@echo "  ui               - Build Rust/Tauri UI (cross-platform)"
	@echo "  release          - Build both agent and Swift UI (release)"
	@echo "  release-agent    - Build agent only (release)"
	@echo "  release-swift-ui - Build Swift UI (release)"
	@echo "  monitor          - Build and run agent in monitor mode (requires sudo)"
	@echo "  enforce          - Build and run agent in enforce mode (requires sudo)"
	@echo "  run-swift-ui     - Run the Swift UI application (macOS)"
	@echo "  run-ui           - Run the Rust UI application (cross-platform)"
	@echo "  test             - Run tests for both projects"
	@echo "  lint             - Run linters for both projects"
	@echo "  clean            - Clean all build artifacts"

build: agent swift-ui ## Build both agent and Swift UI (debug)

agent: ## Build agent only (debug)
	@echo "Building agent (treating warnings as errors)..."
	cargo build -p noswiper
	@echo "✓ Agent built successfully with no warnings"

swift-ui: ## Build Swift UI for macOS (recommended)
	@echo "Building Swift UI for macOS..."
	@cd $(SWIFT_UI_DIR) && ./build.sh Debug
	@echo "✓ Swift UI built successfully"
	@echo "  App bundle: $(SWIFT_UI_DIR)/build/$(MACOS_APP)"

ui: ## Build Rust/Tauri UI (cross-platform)
	@echo "Building Rust/Tauri UI (cross-platform)..."
	@cd $(RUST_UI_DIR) && cargo build
	@echo "✓ Rust UI built successfully"

release: release-agent release-swift-ui ## Build both agent and Swift UI (release)

release-agent: $(OUT_DIR) ## Build agent only (release)
	@echo "Building agent release (treating warnings as errors)..."
	cargo build --release -p noswiper
	cp target/release/$(AGENT_BINARY) $(OUT_DIR)/
	@echo "✓ Agent release binary: $(OUT_DIR)/$(AGENT_BINARY)"

release-swift-ui: $(OUT_DIR) ## Build Swift UI (release)
	@echo "Building Swift UI (release)..."
	@cd $(SWIFT_UI_DIR) && ./build.sh Release
	@echo "Copying app bundle to $(OUT_DIR)..."
	@cp -r $(SWIFT_UI_DIR)/build/$(MACOS_APP) $(OUT_DIR)/
	@echo "✓ Swift UI release: $(OUT_DIR)/$(MACOS_APP)"

monitor: agent ## Build and run agent in monitor mode
	@echo "Starting agent in monitor mode (requires sudo)..."
	sudo ./target/debug/$(AGENT_BINARY) --monitor

enforce: agent ## Build and run agent in enforce mode
	@echo "Starting agent in enforce mode (requires sudo)..."
	sudo ./target/debug/$(AGENT_BINARY)

run-swift-ui: swift-ui ## Run the Swift UI application (macOS)
	@echo "Starting Swift UI..."
	@open $(SWIFT_UI_DIR)/build/$(MACOS_APP)

run-ui: ## Run the Rust UI application (cross-platform)
	@echo "Starting Rust UI..."
	@cd $(RUST_UI_DIR) && cargo tauri dev

test: ## Run tests for both projects
	cargo test --workspace

lint: ## Run linters for both projects
	@echo "Checking formatting..."
	cargo fmt --all --check
	@echo "Running clippy (treating warnings as errors)..."
	cargo clippy --workspace -- -D warnings
	@echo "✓ All lints passed"

clean: ## Clean all build artifacts
	cargo clean
	rm -rf $(OUT_DIR)
	@cd $(SWIFT_UI_DIR) && rm -rf build
	@cd $(RUST_UI_DIR) && cargo clean

$(OUT_DIR):
	mkdir -p $(OUT_DIR)
