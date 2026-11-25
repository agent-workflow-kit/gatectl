"""Helpers for the config tests: write a config (and drop-ins) into a temp dir and load it."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from gatectl.config import LoadedConfig, load_config


def dump(data: Any) -> str:
    """JSON is YAML, so a dict can be written without a YAML emitter."""
    return json.dumps(data)


def write(path: Path, data: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else dump(data), encoding="utf-8")
    return path


def load(
    tmp_path: Path,
    data: Any = None,
    *,
    dropins: Mapping[str, Any] | None = None,
    environ: Mapping[str, str] | None = None,
) -> LoadedConfig:
    """Write ``data`` as ``<tmp>/cfg/config.yaml`` plus drop-ins and load it with ``--config``."""
    main = write(tmp_path / "cfg" / "config.yaml", {} if data is None else data)
    for name, body in (dropins or {}).items():
        write(tmp_path / "cfg" / "config.d" / name, body)
    return load_config(str(main), environ={} if environ is None else environ)


def good_policy(**extra: Any) -> dict[str, Any]:
    """A minimal valid policy body."""
    return {
        "checks": [
            {"name": "r", "type": "rule", "when": [{"path": "a", "op": "exists"}], "then": "deny"}
        ],
        **extra,
    }
