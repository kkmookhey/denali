"""Bounded local JSON loading shared by import-only connectors."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

MAX_JSON_FILE_BYTES = 250 * 1024 * 1024


class JsonImportError(ValueError):
    """An import error that never echoes source-document content."""


def load_json_file(
    path: Path, *, max_bytes: int = MAX_JSON_FILE_BYTES
) -> tuple[Any, str, str]:
    try:
        resolved = path.expanduser().resolve(strict=True)
        size = resolved.stat().st_size
    except OSError as error:
        raise JsonImportError(
            f"cannot read input file ({error.__class__.__name__})"
        ) from error
    if not resolved.is_file():
        raise JsonImportError("input path is not a regular file")
    if size > max_bytes:
        raise JsonImportError(f"input exceeds the {max_bytes} byte safety limit")
    try:
        raw = resolved.read_bytes()
        decoded = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise JsonImportError(f"invalid JSON input ({error.__class__.__name__})") from error
    return decoded, hashlib.sha256(raw).hexdigest(), resolved.as_uri()
