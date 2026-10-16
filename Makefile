.PHONY: help up dev run install test test-cov health clean

.DEFAULT_GOAL := up

HOST ?= 127.0.0.1
PORT ?= 8080

help: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

up: ## Start the FastAPI backend server with auto-reload
	uv run uvicorn app.main:app --reload --host $(HOST) --port $(PORT)

dev: up ## Alias for 'up'

run: up ## Alias for 'up'

install: ## Synchronize project dependencies using uv
	uv sync

test: ## Run the automated pytest test suite
	uv run pytest -v

test-cov: ## Run tests with code coverage report
	uv run pytest --cov=app --cov-report=term-missing

health: ## Check the backend health endpoint
	@curl -s http://$(HOST):$(PORT)/health || echo "Backend is not running at http://$(HOST):$(PORT)"

clean: ## Remove python cache and test artifacts
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
