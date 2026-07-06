from __future__ import annotations

import pytest

from dfcc.canonical import CanonicalizationError, canonical_text, digest_json
from dfcc.jsonpointer import resolve_pointer


def test_canonical_json_sorts_keys() -> None:
    assert canonical_text({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_canonical_json_rejects_float() -> None:
    with pytest.raises(CanonicalizationError):
        canonical_text({"x": 1.2})


def test_digest_is_stable() -> None:
    assert digest_json({"b": 2, "a": 1}) == digest_json({"a": 1, "b": 2})


def test_json_pointer_resolves_escaped_tokens() -> None:
    doc = {"a/b": [{"~key": 3}]}
    assert resolve_pointer(doc, "/a~1b/0/~0key") == 3
