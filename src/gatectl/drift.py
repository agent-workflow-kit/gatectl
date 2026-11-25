"""``definition_changed``: an enforced row whose fingerprint is not the current one.

interface.md, State changes: when the effective state is ``enforced`` and the row that supplies
it has a fingerprint different from the current fingerprint of that row's own scope, ``check``
adds the warning ``definition_changed`` (and ``policies`` shows it). Only the row that supplies
an ``enforced`` state is compared; a row set to ``off`` or ``shadow`` may carry the marker
``setcmd.NO_DEFINITION`` and is never compared. A scope whose definition cannot be computed
counts as changed (fail closed: a warning makes a caller stop acting automatically).
"""

from __future__ import annotations

from gatectl import fingerprint as fingerprint_mod
from gatectl.config import LoadedConfig
from gatectl.errors import ConfigInvalidError, UsageError
from gatectl.scope import Scope
from gatectl.setcmd import NO_DEFINITION
from gatectl.store import Resolved

WARNING = "definition_changed"


def definition_changed(
    config: LoadedConfig,
    name: str,
    resolved: Resolved,
    *,
    scope: str,
    current: str,
) -> bool:
    """Whether ``resolved`` is an enforced state whose row was set for another definition.

    ``scope`` and ``current`` are the decision's scope and the fingerprint already computed for
    it: they stand in for the row's own scope when the row is the decision's own row. A state
    with no single supplying row (the initial state, an indeterminate scope) never warns.
    """
    row = resolved.row
    if row is None or row.state != "enforced":
        return False
    if row.fingerprint == NO_DEFINITION:
        return True
    if row.scope == scope:
        return row.fingerprint != current
    try:
        return row.fingerprint != fingerprint_mod.fingerprint_for(
            config, name, Scope(row.scope, False, ())
        )
    except (ConfigInvalidError, UsageError):
        return True
