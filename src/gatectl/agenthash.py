"""The hash of the current agent configuration (interface.md, State changes, hint 1).

``validate --probe`` (``probe.py``) stores this value as ``probe_agent_hash`` after a successful
probe, and ``set ... enforced`` compares it to decide whether to hint at running the probe. It is
the SHA-256 of the canonical JSON of the ``agent:`` block, the resolved ``session_cmd`` (null when
it does not resolve) and the gatectl version, so changing any of them makes the old probe stale.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from gatectl import __version__
from gatectl.config_models import SharedConfig
from gatectl.inputhash import canonical_input


def agent_config_hash(shared: SharedConfig, session_cmd: Sequence[str] | None) -> str:
    document = {
        "agent": shared.agent.model_dump(mode="json"),
        "session_cmd": None if session_cmd is None else list(session_cmd),
        "version": __version__,
    }
    text = canonical_input(document)
    return "sha256:" + hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()
