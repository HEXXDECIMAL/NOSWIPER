# NoSwiper Makefile
# Build and run commands for both agent and UI

AGENT_BINARY = noswiper-agent
UI_BINARY = noswiper-ui
OUT_DIR = out

.PHONY: all build build-agent build-ui release release-agent release-ui clean monitor enforce test lint help run-ui

# Default target
all: build

help: ## Show this help
	@echo "NoSwiper Makefile"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build       - Build both agent and UI (debug)"
	@echo "  build-agent - Build agent only (debug)"
	@echo "  build-ui    - Build UI only (debug)"
	@echo "  release     - Build both agent and UI (release)"
	@echo "  release-agent - Build agent only (release)"
	@echo "  release-ui  - Build UI only (release)"
	@echo "  monitor     - Build and run agent in monitor mode (requires sudo)"
	@echo "  enforce     - Build and run agent in enforce mode (requires sudo)"
	@echo "  run-ui      - Run the UI application"
	@echo "  test        - Run tests for both projects"
	@echo "  lint        - Run linters for both projects"
	@echo "  clean       - Clean all build artifacts"

build: build-agent build-ui ## Build both agent and UI (debug)

build-agent: ## Build agent only (debug)
	cargo build -p noswiper

build-ui: ## Build UI only (debug)
	cargo build -p noswiper-ui

release: release-agent release-ui ## Build both agent and UI (release)

release-agent: $(OUT_DIR) ## Build agent only (release)
	cargo build --release -p noswiper
	cp target/release/$(AGENT_BINARY) $(OUT_DIR)/
	@echo "Agent release binary: $(OUT_DIR)/$(AGENT_BINARY)"

release-ui: $(OUT_DIR) ## Build UI only (release)
	cargo build --release -p noswiper-ui
	cp target/release/$(UI_BINARY) $(OUT_DIR)/
	@echo "UI release binary: $(OUT_DIR)/$(UI_BINARY)"

monitor: build-agent ## Build and run agent in monitor mode
	@echo "Starting agent in monitor mode (requires sudo)..."
	sudo ./target/debug/$(AGENT_BINARY) --monitor

enforce: build-agent ## Build and run agent in enforce mode
	@echo "Starting agent in enforce mode (requires sudo)..."
	sudo ./target/debug/$(AGENT_BINARY)

run-ui: build-ui ## Run the UI application
	@echo "Starting UI..."
	./target/debug/$(UI_BINARY)

test: ## Run tests for both projects
	cargo test --workspace

lint: ## Run linters for both projects
	cargo fmt --all --check && cargo clippy --workspace -- -D warnings

clean: ## Clean all build artifacts
	cargo clean
	rm -rf $(OUT_DIR)

$(OUT_DIR):
	mkdir -p $(OUT_DIR)
