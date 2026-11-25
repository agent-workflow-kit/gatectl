"""claude-session's CLI schemas, copied here and pinned to one released version.

Test fixtures only: ``src/`` never imports or reads them. To move to a newer claude-session,
re-copy the files from that tag, update ``PINNED_VERSION`` and ``PINNED_COMMIT`` and re-run the
tests; every file carries the pinned version in its ``$comment`` header.

The samples under ``samples/`` were recorded at the sibling tree ``v0.45.2-4-g3ac0daa``, which is
schema-equivalent to the tag (only one description string in ``status.json`` differs).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

PINNED_VERSION = "0.45.2"
PINNED_COMMIT = "c42491578a5309421c1fa67afbdd9f9650fd615b"
PINNED_DIR = Path(__file__).resolve().parent / "pinned" / f"claude-session-{PINNED_VERSION}"
SAMPLES = PINNED_DIR / "samples"
NAMES = ("outcome", "status", "start", "exec", "stop", "list", "forget", "error")


def _document(name: str) -> dict[str, Any]:
    return json.loads((PINNED_DIR / f"{name}.json").read_text(encoding="utf-8"))


def _registry() -> Registry:
    registry: Registry = Registry()
    for name in NAMES:
        resource = Resource.from_contents(_document(name), default_specification=DRAFT202012)
        # ``$ref: outcome.json#...`` resolves against the ``claude-session/cli/`` base of ``$id``.
        registry = registry.with_resource(f"claude-session/cli/{name}.json", resource)
    return registry


def validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(_document(name), registry=_registry())


def errors(name: str, instance: Any) -> list[str]:
    return sorted(e.message for e in validator(name).iter_errors(instance))


def sample(name: str) -> Any:
    """A real claude-session output recorded for parity tests (paths replaced)."""
    return json.loads((SAMPLES / f"real_{name}.json").read_text(encoding="utf-8"))
