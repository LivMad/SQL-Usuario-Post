.PHONY: ruffformat
ruffformat:
	poetry run ruff check . --fix

.PHONY: ruff
ruff:
	poetry run ruff format .

.PHONY: ruffcheck
ruffcheck:
	@echo "Checking ruff..."
	poetry run ruff check .
	poetry run ruff format --check .

.PHONY: poetrycheck
poetrycheck:
	poetry check --lock

.PHONY: pyformatcheck
pyformatcheck: poetrycheck ruffcheck

.PHONY: lint
lint: pyformatcheck

.PHONY: format
format: ruff ruffformat


.PHONY: install
install: 
	poetry install

SHELL := bash

