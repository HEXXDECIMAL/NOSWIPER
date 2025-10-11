# NoSwiper Makefile
# Build and run commands for both agent and UI

AGENT_BINARY = noswiper-agent
UI_BINARY = noswiper-ui
TAURI_UI_DIR = ui-tauri
MACOS_UI_DIR = ui/macos
MACOS_APP = NoSwiper.app
OUT_DIR = out

.PHONY: all build build-agent build-ui build-ui-tauri build-ui-macos release release-agent release-ui release-ui-macos clean monitor enforce test lint help run-ui run-ui-macos

# Default target
all: build

help: ## Show this help
	@echo "NoSwiper Makefile"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build            - Build both agent and macOS UI (debug)"
	@echo "  build-agent      - Build agent only (debug)"
	@echo "  build-ui-macos   - Build native macOS UI (debug)"
	@echo "  build-ui-tauri   - Build Tauri UI (debug, legacy)"
	@echo "  release          - Build both agent and macOS UI (release)"
	@echo "  release-agent    - Build agent only (release)"
	@echo "  release-ui-macos - Build native macOS UI (release)"
	@echo "  monitor          - Build and run agent in monitor mode (requires sudo)"
	@echo "  enforce          - Build and run agent in enforce mode (requires sudo)"
	@echo "  run-ui-macos     - Run the native macOS UI application"
	@echo "  run-ui-tauri     - Run the Tauri UI application (legacy)"
	@echo "  test             - Run tests for both projects"
	@echo "  lint             - Run linters for both projects"
	@echo "  clean            - Clean all build artifacts"

build: build-agent build-ui-macos ## Build both agent and macOS UI (debug)

build-agent: ## Build agent only (debug)
	@echo "Building agent (treating warnings as errors)..."
	cargo build -p noswiper
	@echo "✓ Agent built successfully with no warnings"

build-ui-macos: ## Build native macOS UI (debug)
	@echo "Building native macOS UI..."
	@cd $(MACOS_UI_DIR) && ./build.sh Debug
	@echo "✓ macOS UI built successfully"
	@echo "  App bundle: $(MACOS_UI_DIR)/build/$(MACOS_APP)"

build-ui-tauri: ## Build Tauri UI (debug, legacy)
	@echo "Building Tauri UI (legacy)..."
	@cd $(TAURI_UI_DIR) && cargo build
	@echo "✓ Tauri UI built successfully"

release: release-agent release-ui-macos ## Build both agent and macOS UI (release)

release-agent: $(OUT_DIR) ## Build agent only (release)
	@echo "Building agent release (treating warnings as errors)..."
	cargo build --release -p noswiper
	cp target/release/$(AGENT_BINARY) $(OUT_DIR)/
	@echo "✓ Agent release binary: $(OUT_DIR)/$(AGENT_BINARY)"

release-ui-macos: $(OUT_DIR) ## Build native macOS UI (release)
	@echo "Building native macOS UI (release)..."
	@cd $(MACOS_UI_DIR) && ./build.sh Release
	@echo "Copying app bundle to $(OUT_DIR)..."
	@cp -r $(MACOS_UI_DIR)/build/$(MACOS_APP) $(OUT_DIR)/
	@echo "✓ macOS UI release: $(OUT_DIR)/$(MACOS_APP)"

monitor: build-agent ## Build and run agent in monitor mode
	@echo "Starting agent in monitor mode (requires sudo)..."
	sudo ./target/debug/$(AGENT_BINARY) --monitor

enforce: build-agent ## Build and run agent in enforce mode
	@echo "Starting agent in enforce mode (requires sudo)..."
	sudo ./target/debug/$(AGENT_BINARY)

run-ui-macos: build-ui-macos ## Run the native macOS UI application
	@echo "Starting native macOS UI..."
	@open $(MACOS_UI_DIR)/build/$(MACOS_APP)

run-ui-tauri: ## Run the Tauri UI application (legacy)
	@echo "Starting Tauri UI (legacy)..."
	@cd $(TAURI_UI_DIR) && cargo tauri dev

# Alias for backwards compatibility
run-ui: run-ui-macos

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
	@cd $(MACOS_UI_DIR) && rm -rf build

$(OUT_DIR):
	mkdir -p $(OUT_DIR)
