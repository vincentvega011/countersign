.PHONY: interop-mandates interop-ucp setup node-deps keys dev demo db test test-safety sandbox-smoke eval interop tamper-demo lint deploy

setup: node-deps
	uv sync
	docker compose up -d --wait postgres

# The Node packages the interop verifier needs (jose, canonicalize), installed from the lockfile.
node-deps:
	pnpm install --frozen-lockfile

keys:
	uv run python scripts/generate_keys.py

dev:
	@echo "not implemented yet"

demo:
	@echo "not implemented yet"

db:
	docker compose up -d --wait postgres

test: db
	uv run pytest

test-safety:
	@echo "not implemented yet"

sandbox-smoke:
	uv run python scripts/sandbox_smoke.py

eval:
	@echo "not implemented yet"

# Two independent checks: Python and Node must agree on every shared mandate vector, and the live
# merchant signatures must verify with the Node verifier.
interop: interop-mandates interop-ucp

interop-mandates:
	uv run pytest tests/unit/test_mandate_vectors.py -q
	node scripts/mandate_chain_check.mjs

interop-ucp:
	bash scripts/interop.sh

tamper-demo:
	uv run python scripts/tamper_demo.py

lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy src
	pnpm -r --if-present run lint
	bash scripts/secret_scan.sh

deploy:
	@echo "not implemented yet"
