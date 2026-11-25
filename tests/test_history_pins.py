"""The closed lists the history readers validate against are the schemas' own lists."""

from __future__ import annotations

import json
from pathlib import Path

from gatectl import history

DEFS = json.loads((Path(__file__).resolve().parent.parent / "schemas" / "defs.json").read_text())[
    "$defs"
]


def test_the_closed_lists_equal_the_schema_enums() -> None:
    assert history.REASONS == tuple(DEFS["reason"]["enum"])
    assert history.VERDICTS == tuple(DEFS["verdict"]["enum"])
    assert history.CHECK_TYPES == tuple(DEFS["check_type"]["enum"])
    assert history.DECISIONS == tuple(DEFS["decision"]["enum"])
    assert history.STATES == tuple(DEFS["state"]["enum"])
    assert history.OUTCOMES == tuple(DEFS["outcome"]["enum"])


def test_the_text_caps_equal_the_schema_caps() -> None:
    row = DEFS["decision_row"]["properties"]
    assert row["tool"]["maxLength"] == history.TEXT_CAP
    assert DEFS["check_entry"]["properties"]["detail"]["maxLength"] == history.DETAIL_CAP
