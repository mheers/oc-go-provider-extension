# OpenCode Go Chat Provider for VS Code
# Convenience targets for the most common development tasks.
# All targets delegate to the underlying npm scripts.

NODE    ?= node
NPM     ?= npm
NPM_FLAGS ?=

# VS Code Extension Manager (use npx if not installed globally)
VSCE    ?= npx -y @vscode/vsce

.PHONY: help all install compile watch test test-watch test-coverage \
        lint lint-fix format format-check clean package package-no-deps publish

.DEFAULT_GOAL := help

help: ## Show this help message
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Central "do everything" target: install deps, lint, format, test, then build.
# Stops on the first failure (each step depends on the previous).
all: install lint format test compile ## Install, lint, format, test, and compile

install: ## Install dependencies (also runs dts dev/main via postinstall)
	$(NPM) install $(NPM_FLAGS)

compile: ## Compile TypeScript to ./out
	$(NPM) run compile

watch: ## Compile in watch mode
	$(NPM) run watch

test: ## Run the test suite once
	$(NPM) test

test-watch: ## Run tests in watch mode
	$(NPM) run test:watch

test-coverage: ## Run tests with coverage
	$(NPM) run test:coverage

lint: ## Lint src/ with ESLint
	$(NPM) run lint

lint-fix: ## Lint and auto-fix issues in src/
	$(NPM) run lint:fix

format: ## Format all files with Prettier
	$(NPM) run format

format-check: ## Check formatting without writing
	$(NPM) run format:check

package: ## Build a .vsix package (requires @vscode/vsce)
	$(NPM) run package

package-no-deps: ## Build a .vsix via npx (no global install)
	$(VSCE) package --no-yarn

publish: ## Publish the extension to the VS Code Marketplace
	$(NPM) run publish

clean: ## Remove build artifacts and installed deps
	rm -rf out node_modules
