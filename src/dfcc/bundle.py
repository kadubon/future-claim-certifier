"""Assumption bundle compilation for the finite reference profile."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from dfcc.admission import AcceptedClause
from dfcc.sets import FiniteSet, canonical_key


class BundleCompileError(ValueError):
    """Raised when an assumption bundle cannot be compiled."""


@dataclass(frozen=True, slots=True)
class TransitionRule:
    source: Any
    target: Any
    step: int | None = None


@dataclass(frozen=True, slots=True)
class AssumptionBundle:
    bundle_id: str
    state_space: tuple[Any, ...]
    initial_states: tuple[Any, ...]
    transitions: tuple[TransitionRule, ...]
    admissions: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    validity: dict[str, Any] = field(default_factory=dict)
    scope: tuple[str, ...] = ()
    policy: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CompiledBundle:
    bundle_id: str
    horizon: int
    state_space: FiniteSet
    initial_set: FiniteSet
    transitions_by_step: tuple[dict[str, FiniteSet], ...]
    obligations: tuple[str, ...] = ()
    dependency_graph: tuple[str, ...] = ()
    accepted_clause_refs: tuple[str, ...] = ()
    dependency_graph_ref: str | None = None
    representation_interface_ref: str | None = None
    compiler_identity: str = "dfcc.finite.v1"

    def successors(self, state: Any, step: int) -> FiniteSet:
        key = canonical_key(state)
        if step >= len(self.transitions_by_step):
            return FiniteSet.from_iterable(())
        return self.transitions_by_step[step].get(key, FiniteSet.from_iterable(()))

    def enumerate_trajectories(self) -> FiniteSet:
        trajectories: list[tuple[Any, ...]] = [(state,) for state in self.initial_set]
        for step in range(self.horizon):
            expanded: list[tuple[Any, ...]] = []
            for trajectory in trajectories:
                for successor in self.successors(trajectory[-1], step):
                    expanded.append((*trajectory, successor))
            trajectories = expanded
            if not trajectories:
                break
        return FiniteSet.from_iterable(trajectories)

    def residual_trajectories(self, prefix_set: FiniteSet, r: int) -> FiniteSet:
        if r < 0 or r > self.horizon:
            raise ValueError("prefix index r is outside the horizon")
        prefix_keys = {canonical_key(tuple(prefix)) for prefix in prefix_set}
        return self.enumerate_trajectories().filter(
            lambda trajectory: canonical_key(tuple(trajectory[: r + 1])) in prefix_keys
        )


def parse_bundle(source: Mapping[str, Any]) -> AssumptionBundle:
    bundle_id = source.get("bundle_id")
    if not isinstance(bundle_id, str) or not bundle_id:
        raise BundleCompileError("bundle_id must be a nonempty string")
    state_space = tuple(source.get("state_space", ()))
    initial_states = tuple(source.get("initial_states", ()))
    transitions = []
    for item in source.get("transitions", ()):
        if not isinstance(item, Mapping):
            raise BundleCompileError("transition must be an object")
        transitions.append(
            TransitionRule(
                source=item["from"],
                target=item["to"],
                step=int(item["step"]) if "step" in item and item["step"] is not None else None,
            )
        )
    return AssumptionBundle(
        bundle_id=bundle_id,
        state_space=state_space,
        initial_states=initial_states,
        transitions=tuple(transitions),
        admissions=tuple(str(item) for item in source.get("admissions", ())),
        dependencies=tuple(str(item) for item in source.get("dependencies", ())),
        validity=dict(source.get("validity", {})),
        scope=tuple(str(item) for item in source.get("scope", ())),
        policy=dict(source.get("policy", {})),
    )


def compile_bundle(bundle: AssumptionBundle, horizon: int) -> CompiledBundle:
    state_space = FiniteSet.from_iterable(bundle.state_space)
    initial_set = FiniteSet.from_iterable(bundle.initial_states)
    if not initial_set.keys.issubset(state_space.keys):
        raise BundleCompileError("initial states must be members of state_space")

    transitions_by_step: list[dict[str, list[Any]]] = [{} for _ in range(horizon)]
    for rule in bundle.transitions:
        if canonical_key(rule.source) not in state_space.keys:
            raise BundleCompileError("transition source is not in state_space")
        if canonical_key(rule.target) not in state_space.keys:
            raise BundleCompileError("transition target is not in state_space")
        steps = range(horizon) if rule.step is None else (rule.step,)
        for step in steps:
            if step < 0 or step >= horizon:
                raise BundleCompileError(f"transition step {step} outside horizon")
            by_source = transitions_by_step[step]
            by_source.setdefault(canonical_key(rule.source), []).append(rule.target)

    finite_transitions = tuple(
        {source: FiniteSet.from_iterable(targets) for source, targets in by_source.items()}
        for by_source in transitions_by_step
    )
    return CompiledBundle(
        bundle_id=bundle.bundle_id,
        horizon=horizon,
        state_space=state_space,
        initial_set=initial_set,
        transitions_by_step=finite_transitions,
        obligations=bundle.admissions,
        dependency_graph=bundle.dependencies,
        dependency_graph_ref=f"dependency-graph:{bundle.bundle_id}",
        representation_interface_ref=f"representation-interface:{bundle.bundle_id}:finite",
    )


def assumption_bundle_to_json(bundle: AssumptionBundle) -> dict[str, Any]:
    return {
        "bundle_id": bundle.bundle_id,
        "state_space": list(bundle.state_space),
        "initial_states": list(bundle.initial_states),
        "transitions": [
            {
                "from": rule.source,
                "to": rule.target,
                **({"step": rule.step} if rule.step is not None else {}),
            }
            for rule in bundle.transitions
        ],
        "admissions": list(bundle.admissions),
        "dependencies": list(bundle.dependencies),
        "validity": dict(bundle.validity),
        "scope": list(bundle.scope),
        "policy": dict(bundle.policy),
    }


def assumption_bundle_from_accepted_clauses(
    base: Mapping[str, Any],
    accepted_clauses: tuple[AcceptedClause, ...],
) -> AssumptionBundle:
    """Construct the finite bundle from accepted semantic clauses only."""

    state_space: list[Any] = []
    initial_states: list[Any] = []
    transitions: list[Any] = []
    admissions: list[str] = []
    dependencies: list[str] = []
    validity = dict(base.get("validity", {}))
    source = {
        "bundle_id": base.get("bundle_id", "accepted-clause-bundle"),
        "state_space": state_space,
        "initial_states": initial_states,
        "transitions": transitions,
        "admissions": admissions,
        "dependencies": dependencies,
        "validity": validity,
        "scope": tuple(str(item) for item in base.get("scope", ())),
        "policy": dict(base.get("policy", {})),
    }
    for accepted in accepted_clauses:
        clause = accepted.clause
        admissions.append(accepted.clause_id)
        dependencies.extend(accepted.obligation_refs)
        if "state_space" in clause:
            state_space.extend(clause["state_space"])
        if "initial_states" in clause:
            initial_states.extend(clause["initial_states"])
        if "transitions" in clause:
            transitions.extend(clause["transitions"])
        if "validity" in clause and isinstance(clause["validity"], Mapping):
            validity.update(clause["validity"])
    return parse_bundle(source)


def compile_bundle_from_accepted_clauses(
    base: Mapping[str, Any],
    accepted_clauses: tuple[AcceptedClause, ...],
    horizon: int,
) -> CompiledBundle:
    bundle = assumption_bundle_from_accepted_clauses(base, accepted_clauses)
    compiled = compile_bundle(bundle, horizon)
    return CompiledBundle(
        bundle_id=compiled.bundle_id,
        horizon=compiled.horizon,
        state_space=compiled.state_space,
        initial_set=compiled.initial_set,
        transitions_by_step=compiled.transitions_by_step,
        obligations=compiled.obligations,
        dependency_graph=compiled.dependency_graph,
        accepted_clause_refs=tuple(clause.clause_id for clause in accepted_clauses),
        dependency_graph_ref=compiled.dependency_graph_ref,
        representation_interface_ref=compiled.representation_interface_ref,
        compiler_identity=compiled.compiler_identity,
    )
