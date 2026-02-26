SHELL := /bin/bash

.PHONY: install dev lint test audit run

install:
	python -m pip install -U pip
	pip install -e .

dev:
	pip install -e ".[dev]"

lint:
	ruff check .
	ruff format .

test:
	pytest -q

audit:
	pip-audit -r <(python -c "import tomllib; print('\n'.join(tomllib.load(open('pyproject.toml','rb'))['project']['dependencies']))") || true

run:
	uvicorn guardrails.app:app --host 0.0.0.0 --port 8000
