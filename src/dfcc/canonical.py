"""Canonical JSON and digest utilities.

DFCC uses canonical bytes as identity inputs. This implementation follows the
RFC 8785 shape for JSON objects used by DFCC artifacts: sorted object members,
UTF-8 bytes, no insignificant whitespace, and no NaN/Infinity. To avoid binary
floating-point ambiguity required by the paper, Python floats are rejected.
Decimal quantities should be encoded as strings in wire records.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from dfcc.serialization import to_jsonable

SUPPORTED_DIGESTS = {"sha256", "sha384", "sha512"}


class CanonicalizationError(ValueError):
    """Raised when a value cannot be canonically encoded for DFCC identity."""


def _reject_unsafe_numbers(value: Any, path: str = "") -> None:
    if isinstance(value, float):
        raise CanonicalizationError(
            f"binary floating-point value at {path or '/'} is not permitted; "
            "encode authority-relevant decimals as strings"
        )
    if isinstance(value, Decimal):
        raise CanonicalizationError(
            f"Decimal object at {path or '/'} must be serialized as an explicit string"
        )
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"non-string JSON object key at {path or '/'}")
            _reject_unsafe_numbers(item, f"{path}/{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_unsafe_numbers(item, f"{path}/{index}")
    elif not isinstance(value, (str, int, bool, type(None))):
        raise CanonicalizationError(f"unsupported JSON value at {path or '/'}: {type(value)!r}")


def canonical_bytes(value: Any) -> bytes:
    jsonable = to_jsonable(value)
    _reject_unsafe_numbers(jsonable)
    text = json.dumps(
        jsonable,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return text.encode("utf-8")


def canonical_text(value: Any) -> str:
    return canonical_bytes(value).decode("utf-8")


def digest_bytes(data: bytes, algorithm: str = "sha256") -> str:
    normalized = algorithm.lower()
    if normalized not in SUPPORTED_DIGESTS:
        raise ValueError(f"unsupported digest algorithm: {algorithm}")
    h = hashlib.new(normalized)
    h.update(data)
    return f"{normalized}:{h.hexdigest()}"


def digest_json(value: Any, algorithm: str = "sha256") -> str:
    return digest_bytes(canonical_bytes(value), algorithm)


@dataclass(frozen=True, slots=True)
class ManifestInput:
    domain_tag: str
    type_tag: str
    declared_digest_algorithm: str
    schema_profile_digest: str
    artifact: Any
    ordered_semantic_dependency_digests: tuple[str, ...] = ()


def manifest_digest(
    artifact: Any,
    *,
    domain_tag: str,
    type_tag: str,
    schema_profile_digest: str,
    dependencies: Iterable[str] = (),
    algorithm: str = "sha256",
) -> str:
    """Compute the domain-separated manifest digest described by the paper."""

    ordered = tuple(sorted(dependencies))
    payload = ManifestInput(
        domain_tag=domain_tag,
        type_tag=type_tag,
        declared_digest_algorithm=algorithm.lower(),
        schema_profile_digest=schema_profile_digest,
        artifact=artifact,
        ordered_semantic_dependency_digests=ordered,
    )
    return digest_json(payload, algorithm)
