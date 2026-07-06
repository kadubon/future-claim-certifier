from __future__ import annotations

from decimal import Decimal

import pytest

from dfcc.canonical import CanonicalizationError, canonical_text, digest_bytes, digest_json
from dfcc.jsonpointer import resolve_pointer


def test_canonical_json_sorts_keys() -> None:
    assert canonical_text({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_canonical_json_uses_jcs_string_escaping() -> None:
    assert canonical_text({"x": "\u2028"}) == '{"x":"\u2028"}'


def test_canonical_json_rejects_float() -> None:
    with pytest.raises(CanonicalizationError):
        canonical_text({"x": 1.2})


def test_canonical_json_rejects_non_finite_and_decimal_objects() -> None:
    with pytest.raises(CanonicalizationError):
        canonical_text({"x": float("nan")})
    with pytest.raises(CanonicalizationError):
        canonical_text({"x": float("inf")})
    with pytest.raises(CanonicalizationError):
        canonical_text({"x": Decimal("1.0")})


def test_canonical_json_rejects_non_json_shapes() -> None:
    with pytest.raises(CanonicalizationError):
        canonical_text({1: "not a string key"})
    with pytest.raises(CanonicalizationError):
        canonical_text({"x": object()})


def test_digest_rejects_unknown_algorithm() -> None:
    with pytest.raises(ValueError, match="unsupported digest algorithm"):
        digest_bytes(b"{}", "sha1")


def test_digest_is_stable() -> None:
    assert digest_json({"b": 2, "a": 1}) == digest_json({"a": 1, "b": 2})


def test_json_pointer_resolves_escaped_tokens() -> None:
    doc = {"a/b": [{"~key": 3}]}
    assert resolve_pointer(doc, "/a~1b/0/~0key") == 3
