.PHONY: verify test live lint fmt fmt-check typecheck mdlint schemacheck

verify: lint fmt-check typecheck test mdlint schemacheck

test:
	uv run pytest

# Live tests: the REAL claude-session and a REAL model. BILLED, and they use the logged-in
# accounts. Never part of verify or CI; they need an explicit GATECTL_LIVE=1. The check runs at
# parse time, so `make -i`, `-k`, `-B` and MAKEFLAGS cannot skip it (a recipe error can be ignored).
ifneq ($(filter live,$(MAKECMDGOALS)),)
ifneq ($(strip $(GATECTL_LIVE)),1)
$(error make live runs the real claude-session and a real model and is BILLED. Confirm with: make live GATECTL_LIVE=1 (GATECTL_LIVE is not 1; see docs/design.md, Live test map))
endif
endif

live:
	@echo "WARNING: the live tests are BILLED (about 20 model runs of GATECTL_LIVE_MODEL, default haiku; the cost is not measured) and use your login."
	@test "$(GATECTL_LIVE_HOME)" != "real" || echo "WARNING: GATECTL_LIVE_HOME=real: the tests use your REAL ~/.claude (hostile-input transcripts land in ~/.claude/projects, a token refresh may rewrite ~/.claude.json and sign out your install). Prefer an API key and the private home."
	GATECTL_LIVE=1 uv run pytest -m live -s -v -rs -p no:cacheprovider; code=$$?; echo "NOTE: skipped live tests prove nothing: read the -rs lines above and check the passed count."; exit $$code

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
