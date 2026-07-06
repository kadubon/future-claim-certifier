"""Serialization helpers for DFCC dataclasses."""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from datetime import UTC, datetime
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any


def to_jsonable(value: Any) -> Any:
    """Convert DFCC objects into JSON-compatible structures.

    Authority-relevant decimal values are emitted as strings. Binary floats are
    intentionally left to canonicalization, where they are rejected.
    """

    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, datetime):
        dt = value.astimezone(UTC) if value.tzinfo else value
        text = dt.isoformat()
        return text.replace("+00:00", "Z")
    if isinstance(value, Path):
        return str(value)
    to_json = getattr(value, "to_json", None)
    if callable(to_json) and not isinstance(value, type):
        return to_jsonable(to_json())
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: to_jsonable(getattr(value, field.name))
            for field in fields(value)
            if getattr(value, field.name) is not None
        }
    if isinstance(value, tuple | list):
        return [to_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    return value
