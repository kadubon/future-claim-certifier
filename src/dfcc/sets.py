"""Finite set helpers used by the reference backend.

The paper permits arbitrary set representations through SetRef records. This
module is intentionally finite and exact; it is the portable reference backend,
not a replacement for reachability tools.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from dfcc.canonical import canonical_text


def canonical_key(value: Any) -> str:
    return canonical_text(value)


@dataclass(frozen=True)
class FiniteSet:
    _items: tuple[Any, ...]
    _keys: frozenset[str]

    @classmethod
    def from_iterable(cls, values: Iterable[Any]) -> FiniteSet:
        by_key: dict[str, Any] = {}
        for value in values:
            by_key[canonical_key(value)] = value
        keys = tuple(sorted(by_key))
        return cls(tuple(by_key[key] for key in keys), frozenset(keys))

    def __iter__(self) -> Iterator[Any]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __contains__(self, item: object) -> bool:
        return canonical_key(item) in self._keys

    @property
    def items(self) -> tuple[Any, ...]:
        return self._items

    @property
    def keys(self) -> frozenset[str]:
        return self._keys

    def is_empty(self) -> bool:
        return not self._items

    def subset_of(self, other: FiniteSet) -> bool:
        return self._keys.issubset(other._keys)

    def disjoint_from(self, other: FiniteSet) -> bool:
        return self._keys.isdisjoint(other._keys)

    def intersection(self, other: FiniteSet) -> FiniteSet:
        return FiniteSet.from_iterable(item for item in self if canonical_key(item) in other._keys)

    def union(self, other: FiniteSet) -> FiniteSet:
        return FiniteSet.from_iterable((*self._items, *other._items))

    def filter(self, predicate: Any) -> FiniteSet:
        return FiniteSet.from_iterable(item for item in self if predicate(item))

    def to_json(self) -> list[Any]:
        return list(self._items)


EMPTY_SET = FiniteSet.from_iterable(())
