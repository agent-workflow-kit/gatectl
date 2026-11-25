"""Validate records against the repo's ``schemas/`` (draft 2020-12, cross-file ``$ref``)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

SCHEMAS = Path(__file__).resolve().parent.parent / "schemas"


def _registry() -> Registry:
    registry: Registry = Registry()
    for name in ("defs", "audit", "log"):
        document = json.loads((SCHEMAS / f"{name}.json").read_text(encoding="utf-8"))
        resource = Resource.from_contents(document, default_specification=DRAFT202012)
        # ``$ref: defs.json#...`` resolves against the ``gatectl/`` base of each ``$id``.
        registry = registry.with_resource(f"gatectl/{name}.json", resource)
    return registry


def validator(name: str) -> Draft202012Validator:
    document = json.loads((SCHEMAS / f"{name}.json").read_text(encoding="utf-8"))
    return Draft202012Validator(document, registry=_registry())


def errors(name: str, record: Mapping[str, Any]) -> list[str]:
    return [e.message for e in validator(name).iter_errors(record)]


def assert_valid(name: str, record: Mapping[str, Any]) -> None:
    found = errors(name, record)
    assert not found, found
