"""Bounded claim language and compiler.

The kernel requires a bounded language whose compiler produces satisfaction
sets over finite represented trajectories. This module uses a JSON AST so
agents can construct claims without depending on a parser.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

from dfcc.sets import FiniteSet

Predicate = Callable[[Any, tuple[Any, ...], int, Mapping[str, Any]], bool]


class ClaimCompileError(ValueError):
    """Raised when a claim source cannot be compiled."""


@dataclass(frozen=True, slots=True)
class ClaimRecord:
    claim_id: str
    horizon: int
    formula: dict[str, Any]
    scope: tuple[str, ...] = ()
    predicate_registry_digest: str | None = None

    def satisfies(self, trajectory: tuple[Any, ...], registry: PredicateRegistry) -> bool:
        if len(trajectory) != self.horizon + 1:
            return False
        return evaluate_formula(self.formula, trajectory, 0, self.horizon, registry)

    def satisfaction_set(self, trajectories: FiniteSet, registry: PredicateRegistry) -> FiniteSet:
        return trajectories.filter(lambda item: self.satisfies(tuple(item), registry))


class PredicateRegistry:
    def __init__(self) -> None:
        self._predicates: dict[str, Predicate] = {}

    def register(self, name: str, predicate: Predicate) -> None:
        if not name:
            raise ValueError("predicate name must be nonempty")
        self._predicates[name] = predicate

    def get(self, name: str) -> Predicate:
        try:
            return self._predicates[name]
        except KeyError as exc:
            raise ClaimCompileError(f"unknown predicate: {name}") from exc

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._predicates))


def _as_decimal(value: Any) -> Decimal:
    try:
        return Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError(f"not a decimal-compatible value: {value!r}") from exc


def _field_value(state: Any, field: str) -> Any:
    current = state
    for part in field.split("."):
        current = current[part] if isinstance(current, dict) else getattr(current, part)
    return current


def field_cmp(
    state: Any, _trajectory: tuple[Any, ...], _index: int, args: Mapping[str, Any]
) -> bool:
    left = _as_decimal(_field_value(state, str(args["field"])))
    right = _as_decimal(args["value"])
    op = args["op"]
    if op == "lt":
        return left < right
    if op == "lte":
        return left <= right
    if op == "gt":
        return left > right
    if op == "gte":
        return left >= right
    if op == "eq":
        return left == right
    if op == "ne":
        return left != right
    raise ValueError(f"unknown comparison operator: {op}")


def field_eq(
    state: Any, _trajectory: tuple[Any, ...], _index: int, args: Mapping[str, Any]
) -> bool:
    return bool(_field_value(state, str(args["field"])) == args["value"])


def state_in(
    state: Any, _trajectory: tuple[Any, ...], _index: int, args: Mapping[str, Any]
) -> bool:
    values = args.get("values")
    if not isinstance(values, list):
        raise ValueError("state_in requires args.values as a list")
    return any(state == value for value in values)


def always_true(
    _state: Any, _trajectory: tuple[Any, ...], _index: int, _args: Mapping[str, Any]
) -> bool:
    return True


def always_false(
    _state: Any, _trajectory: tuple[Any, ...], _index: int, _args: Mapping[str, Any]
) -> bool:
    return False


def default_predicate_registry() -> PredicateRegistry:
    registry = PredicateRegistry()
    registry.register("field_cmp", field_cmp)
    registry.register("field_eq", field_eq)
    registry.register("state_in", state_in)
    registry.register("true", always_true)
    registry.register("false", always_false)
    return registry


def _require_interval(node: Mapping[str, Any], horizon: int) -> tuple[int, int]:
    try:
        start = int(node["a"])
        end = int(node["b"])
    except KeyError as exc:
        raise ClaimCompileError("temporal operator requires integer a and b bounds") from exc
    if start < 0 or end < start or end > horizon:
        raise ClaimCompileError(f"invalid temporal interval [{start}, {end}] for horizon {horizon}")
    return start, end


def validate_formula(node: Mapping[str, Any], horizon: int, registry: PredicateRegistry) -> None:
    op = node.get("op")
    if op == "atom":
        name = node.get("name")
        if not isinstance(name, str):
            raise ClaimCompileError("atom requires a string name")
        registry.get(name)
        if "args" in node and not isinstance(node["args"], dict):
            raise ClaimCompileError("atom args must be an object")
        return
    if op == "not":
        validate_formula(_child(node), horizon, registry)
        return
    if op in {"and", "or"}:
        children = node.get("children")
        if not isinstance(children, list) or not children:
            raise ClaimCompileError(f"{op} requires a nonempty children list")
        for child in children:
            if not isinstance(child, dict):
                raise ClaimCompileError(f"{op} child must be an object")
            validate_formula(child, horizon, registry)
        return
    if op in {"G", "F"}:
        _require_interval(node, horizon)
        validate_formula(_child(node), horizon, registry)
        return
    if op == "U":
        _require_interval(node, horizon)
        left = node.get("left")
        right = node.get("right")
        if not isinstance(left, dict) or not isinstance(right, dict):
            raise ClaimCompileError("U requires left and right formula objects")
        validate_formula(left, horizon, registry)
        validate_formula(right, horizon, registry)
        return
    raise ClaimCompileError(f"unknown formula operator: {op!r}")


def _child(node: Mapping[str, Any]) -> Mapping[str, Any]:
    child = node.get("child")
    if not isinstance(child, dict):
        raise ClaimCompileError("formula child must be an object")
    return child


def evaluate_formula(
    node: Mapping[str, Any],
    trajectory: tuple[Any, ...],
    index: int,
    horizon: int,
    registry: PredicateRegistry,
) -> bool:
    op = node["op"]
    if op == "atom":
        predicate = registry.get(str(node["name"]))
        args = node.get("args", {})
        if not isinstance(args, Mapping):
            raise ClaimCompileError("atom args must be an object")
        return predicate(trajectory[index], trajectory, index, args)
    if op == "not":
        return not evaluate_formula(_child(node), trajectory, index, horizon, registry)
    if op == "and":
        return all(
            evaluate_formula(child, trajectory, index, horizon, registry)
            for child in node["children"]
        )
    if op == "or":
        return any(
            evaluate_formula(child, trajectory, index, horizon, registry)
            for child in node["children"]
        )
    if op == "G":
        start, end = _require_interval(node, horizon)
        child = _child(node)
        return all(
            evaluate_formula(child, trajectory, index + offset, horizon, registry)
            for offset in range(start, end + 1)
        )
    if op == "F":
        start, end = _require_interval(node, horizon)
        child = _child(node)
        return any(
            evaluate_formula(child, trajectory, index + offset, horizon, registry)
            for offset in range(start, end + 1)
        )
    if op == "U":
        start, end = _require_interval(node, horizon)
        left = node["left"]
        right = node["right"]
        for offset in range(start, end + 1):
            pivot = index + offset
            if evaluate_formula(right, trajectory, pivot, horizon, registry) and all(
                evaluate_formula(left, trajectory, j, horizon, registry)
                for j in range(index, pivot)
            ):
                return True
        return False
    raise ClaimCompileError(f"unknown formula operator: {op!r}")


def compile_claim(
    source: Mapping[str, Any],
    registry: PredicateRegistry | None = None,
) -> ClaimRecord:
    registry = registry or default_predicate_registry()
    claim_id = source.get("claim_id")
    if not isinstance(claim_id, str) or not claim_id:
        raise ClaimCompileError("claim_id must be a nonempty string")
    horizon = int(source["horizon"])
    if horizon < 0:
        raise ClaimCompileError("horizon must be nonnegative")
    formula = source.get("formula")
    if not isinstance(formula, dict):
        raise ClaimCompileError("formula must be an object")
    validate_formula(formula, horizon, registry)
    scope = tuple(str(item) for item in source.get("scope", ()))
    return ClaimRecord(claim_id=claim_id, horizon=horizon, formula=formula, scope=scope)
