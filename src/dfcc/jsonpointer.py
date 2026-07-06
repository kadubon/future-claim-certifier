"""Small RFC 6901 JSON Pointer resolver."""

from __future__ import annotations

from typing import Any


class JsonPointerError(KeyError):
    """Raised when a JSON Pointer cannot be resolved."""


def _unescape(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def resolve_pointer(document: Any, pointer: str) -> Any:
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        raise JsonPointerError(f"invalid JSON Pointer: {pointer!r}")

    current = document
    for raw_token in pointer.split("/")[1:]:
        token = _unescape(raw_token)
        if isinstance(current, list):
            if token == "-":
                raise JsonPointerError("'-' token does not select an existing array element")
            try:
                index = int(token)
            except ValueError as exc:
                raise JsonPointerError(f"array token is not an integer: {token!r}") from exc
            try:
                current = current[index]
            except IndexError as exc:
                raise JsonPointerError(f"array index out of range: {index}") from exc
        elif isinstance(current, dict):
            try:
                current = current[token]
            except KeyError as exc:
                raise JsonPointerError(f"object key not found: {token!r}") from exc
        else:
            raise JsonPointerError(f"cannot descend into {type(current).__name__}")
    return current
