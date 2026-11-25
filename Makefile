.PHONY: verify test lint fmt fmt-check typecheck mdlint schemacheck

verify: lint fmt-check typecheck test mdlint schemacheck

test:
	uv run pytest

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
