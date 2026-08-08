"""UUID utilities shim used by the package.

This module provides a small wrapper around the standard library's
`uuid.uuid4()` so modules that import `uuid4` keep working. We put it
under `aries_cloudagent.utils` and import it with a package-relative
import to avoid depending on a top-level `uuid_utils` package that may
not be installed.
"""

from __future__ import annotations

import uuid
from typing import Any


def uuid4() -> Any:
    """Return a new UUID value.

    The original codebase sometimes expects a string, sometimes a
    UUID-like object. For compatibility we return a UUID instance; call
    sites that expect strings usually convert with `str()`.
    """

    return uuid.uuid4()
