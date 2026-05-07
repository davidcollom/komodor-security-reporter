.PHONY: help test build lint fmt clean docker-build install-tools coverage bench bench-report bench-reconcile bench-reconcile-smoke bench-reconcile-report

help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

install-tools: ## Install development tools
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install gotest.tools/gotestsum@latest
	go install github.com/goreleaser/goreleaser@latest

fmt: ## Format code
	@echo "Formatting code..."
	gofmt -s -w .
	goimports -w .

lint: ## Run linters
	@echo "Running linters..."
	golangci-lint run ./...

test: ## Run tests
	@echo "Running tests..."
	go test -v -race -timeout 10m ./...

coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-short: ## Run short tests only
	@echo "Running short tests..."
	go test -short -v ./...

bench: ## Run all benchmark functions without running normal tests
	@echo "Running all benchmarks..."
	go test -run '^$$' -bench . -benchmem -benchtime=1x ./...

bench-report: ## Generate repo-wide benchmark report output
	@echo "Generating benchmark report..."
	mkdir -p docs/benchmarks/results
	go test -run '^$$' -bench . -benchmem -benchtime=1x -count=3 ./... | tee docs/benchmarks/results/latest.txt

bench-reconcile: ## Run reconciler benchmark suite
	@echo "Running reconciler benchmarks..."
	go test -run '^$$' -bench BenchmarkReconcileAllScenarios -benchmem ./internal/reconciler

bench-reconcile-smoke: ## Run quick benchmark smoke checks
	@echo "Running reconciler benchmark smoke checks..."
	go test -run '^$$' -short -bench BenchmarkReconcileAllScenarios -benchmem -benchtime=1x ./internal/reconciler

bench-reconcile-report: ## Generate benchmark report output
	@echo "Generating reconciler benchmark report..."
	mkdir -p docs/benchmarks/results
	go test -run '^$$' -bench BenchmarkReconcileAllScenarios -benchmem -benchtime=1x -count=3 ./internal/reconciler | tee docs/benchmarks/results/latest.txt

build: ## Build the application
	@echo "Building..."
	go build -o bin/komodor-security-reporter ./cmd/komodor-security-reporter

run: build ## Build and run the application
	@echo "Running..."
	./bin/komodor-security-reporter -config ./docs/example-config.yaml

docker-build: ## Build Docker images via GoReleaser snapshot (no publish)
	@echo "Building Docker images via GoReleaser snapshot..."
	goreleaser release --snapshot --clean --skip=publish

clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -rf bin/
	rm -f coverage.out coverage.html

tidy: ## Tidy dependencies
	@echo "Tidying dependencies..."
	go mod tidy
	go mod verify

vet: ## Run go vet
	@echo "Running go vet..."
	go vet ./...

check: lint vet test ## Run all checks

release-snapshot: ## Build release snapshot
	@echo "Building release snapshot..."
	goreleaser build --snapshot --clean

release: ## Create a release (requires git tag)
	@echo "Creating release..."
	goreleaser release

pre-commit-install: ## Install pre-commit hooks
	@echo "Installing pre-commit hooks..."
	pre-commit install
	pre-commit run --all-files

pre-commit-uninstall: ## Uninstall pre-commit hooks
	@echo "Uninstalling pre-commit hooks..."
	pre-commit uninstall
