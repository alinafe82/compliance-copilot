.PHONY: setup install lint format type-check test test-cov test-fast security run docker clean help

help:  ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: install  ## Setup development environment
	pre-commit install
	@echo "✓ Development environment ready"

install:  ## Install dependencies
	uv venv
	. .venv/bin/activate && uv pip install -e .[dev]

lint:  ## Run linting checks (ruff + mypy)
	ruff check .
	mypy src

format:  ## Auto-format code
	ruff check . --fix
	ruff format .
	isort .
	black .

type-check:  ## Run type checking
	mypy src

test:  ## Run tests
	pytest

test-cov:  ## Run tests with coverage report
	pytest --cov=src --cov-report=term-missing --cov-report=html
	@echo "Coverage report: htmlcov/index.html"

test-fast:  ## Run tests with fail-fast
	pytest --maxfail=1 -x

security:  ## Run security checks
	uvx gitleaks detect --no-git -v
	uvx bandit -r src
	uvx safety check

run:  ## Run development server
	uv run uvicorn src.app:app --reload --port 8000

docker:  ## Build Docker image
	docker build -t ghcr.io/${USER}/compliance-copilot:local .

docker-run:  ## Run Docker container locally
	docker run -p 8000:8000 ghcr.io/${USER}/compliance-copilot:local

clean:  ## Clean up generated files
	rm -rf .venv
	rm -rf htmlcov
	rm -rf .coverage
	rm -rf .pytest_cache
	rm -rf .ruff_cache
	rm -rf .mypy_cache
	rm -rf dist
	rm -rf build
	rm -rf *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

ci:  ## Run full CI pipeline locally
	@echo "Running linting..."
	@$(MAKE) lint
	@echo "Running tests with coverage..."
	@$(MAKE) test-cov
	@echo "Running security checks..."
	@$(MAKE) security
	@echo "✓ All CI checks passed"
