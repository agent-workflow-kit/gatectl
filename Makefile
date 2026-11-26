.PHONY: verify test live lint fmt fmt-check typecheck mdlint schemacheck

verify: lint fmt-check typecheck test mdlint schemacheck

test:
	uv run pytest

# Live tests: the REAL claude-session and a REAL model. BILLED, and they use the logged-in
# accounts. Never part of verify or CI; they need an explicit GATECTL_LIVE=1.
live:
	@test "$(GATECTL_LIVE)" = "1" || { echo "make live runs the real claude-session and a real model and is BILLED."; echo "Confirm with: make live GATECTL_LIVE=1 (see docs/design.md, Live test map)"; exit 1; }
	@echo "WARNING: the live tests are BILLED (about 20 haiku runs, a few cents) and use your login."
	GATECTL_LIVE=1 uv run pytest -m live -s -v -p no:cacheprovider

lint:
	uv run ruff check .

fmt:
	uv run ruff format .

fmt-check:
	uv run ruff format --check .

typecheck:
	uv run pyright

mdlint:
	uv run pymarkdown --config .pymarkdown.json scan -r --respect-gitignore .

schemacheck:
	uv run check-jsonschema --schemafile schemas/config.json config.example.yaml
