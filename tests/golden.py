"""The golden-file harness: a golden file is the exact bytes a command prints.

``load`` reads a golden file, checks that it is one line of canonical JSON (the form
``gatectl.cli.render_json`` prints) and validates it against the schema in ``schemas/`` that
documents its shape. ``assert_output`` then compares a command's real output to the file byte for
byte. To add a shape: write the file in ``tests/golden/``, add it to ``SHAPES`` and, when the shape
has a command, to ``COMMAND_OF``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from gatectl.cli import render_json
from tests import schema_util

GOLDEN_DIR = Path(__file__).resolve().parent / "golden"

# golden file stem -> schema name under schemas/
SHAPES: dict[str, str] = {
    "check-shadow-allow": "cli/check",
    "check-enforced-deny": "cli/check",
    "check-not-applicable": "cli/check",
    "check-dry-run": "cli/check-dry-run",
    "outcome": "cli/outcome",
    "decisions": "cli/decisions",
    "show": "cli/show",
    "stats": "cli/stats",
    "set": "cli/set",
    "policies": "cli/policies",
    "validate": "cli/validate",
    "reconcile": "cli/reconcile",
    "prune": "cli/prune",
    "cron": "cli/cron",
    "error-usage": "cli/error",
}


def load(
    name: str, schema: str | None = None, directory: Path = GOLDEN_DIR
) -> tuple[bytes, dict[str, Any]]:
    """Return the file's bytes and parsed document after checking form and schema."""
    raw = (directory / f"{name}.json").read_bytes()
    document = json.loads(raw)
    assert isinstance(document, dict), f"{name}: a golden file holds one JSON object"
    assert raw == render_json(document).encode("ascii"), f"{name}: not in canonical output form"
    schema_util.assert_valid(schema or SHAPES[name], document)
    return raw, document


def assert_output(
    name: str, actual: str, schema: str | None = None, directory: Path = GOLDEN_DIR
) -> None:
    """Compare ``actual`` (a command's stdout) to the golden file byte for byte."""
    expected, _ = load(name, schema, directory)
    assert actual.encode("utf-8") == expected, f"{name}: output differs from the golden file"
