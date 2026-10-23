.PHONY: setup keys dev demo test test-safety sandbox-smoke eval interop tamper-demo lint deploy

setup:
	uv sync
	pnpm install
	docker compose up -d --wait postgres

keys:
	@echo "not implemented yet"

dev:
	@echo "not implemented yet"

demo:
	@echo "not implemented yet"

test:
	uv run pytest

test-safety:
	@echo "not implemented yet"

sandbox-smoke:
	uv run python scripts/sandbox_smoke.py

eval:
	@echo "not implemented yet"

interop:
	@echo "not implemented yet"

tamper-demo:
	@echo "not implemented yet"

lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy src
	pnpm -r --if-present run lint
	bash scripts/secret_scan.sh

deploy:
	@echo "not implemented yet"
