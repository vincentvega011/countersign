.PHONY: dev-pair interop-mandates interop-ucp setup node-deps keys dev demo db test test-safety sandbox-smoke eval interop tamper-demo lint deploy

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

# A full and a baseline instance side by side, each on its own database (docs/architecture.md).
dev-pair: db keys
	uv run python scripts/dev_pair.py

demo:
	@echo "not implemented yet"

db:
	docker compose up -d --wait postgres

test: db
	uv run pytest

# The tests of the modules that decide about money, identity and evidence, plus the structural guards
# (import guards, the capture surface) and strict typing. Everything except the catalog and CI-file
# tests, which are not safety relevant; scripts/safety_coverage.py checks that every invariant package
# is imported by some test.
test-safety: db
	uv run mypy src
	uv run python scripts/safety_coverage.py
	uv run pytest tests --ignore=tests/unit/test_catalog.py --ignore=tests/properties/test_catalog_properties.py --ignore=tests/unit/test_ci_workflow.py

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
