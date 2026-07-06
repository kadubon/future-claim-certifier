# Documentation Index

This page is the shortest path into Future Claim Certifier. The protocol has
formal names, but the basic idea is simple: preserve the evidence for a
time-bound claim, replay it later, and return a typed answer with reasons.

## Start Here

- New user: read the [README](../README.md), then run the safe-temperature CLI
  example.
- Agent builder: read [Agent Usage](agent-usage.md), especially the outcome
  handling rules.
- Protocol implementer: read [Architecture](architecture.md), then
  [Protocol Mapping](protocol-mapping.md).
- Release maintainer: use the [Release Checklist](release-checklist.md).
- Security reviewer: read the [Security Policy](../SECURITY.md), then run the
  release checklist scans.

## Common Terms

- Claim: a statement about future states, such as "temperature stays at or
  below 80 for the next two steps".
- Certificate: an issue-time record that says what was checked, under which
  assumptions, and with which time basis.
- Artifact: a canonical JSON object with a digest and role.
- Replay: recomputing a decision from artifacts instead of trusting a stored
  answer.
- Status time: the time when someone wants to use the certificate.
- Authority outcome: the final typed result, such as `assert`, `deny`,
  `accept`, `reject`, `unknown`, or `expired`.
- Blocking record: a structured reason that prevents an allowing outcome.

## Main Workflows

Use a finite example:

```bash
uv run dfcc certify examples/safe_temperature/spec.json --out issue.json
uv run dfcc check issue.json \
  examples/safe_temperature/proposed_use.json \
  examples/safe_temperature/status_context.json \
  --out status-view.json
```

Use strict artifact replay:

```bash
uv run dfcc certify-bundle artifact-bundle.json --out issue.json
uv run dfcc validate-bundle artifact-bundle.json --full-replay
uv run dfcc replay-status --bundle artifact-bundle.json
```

Use the strict replay path for authority. Direct file or dictionary checks are
compatibility helpers unless the returned view proves that all artifact
references, accepted clauses, proof records, and blocking records were replayed.

Check conformance:

```bash
uv run dfcc conformance run --suite primary
uv run dfcc conformance run --suite strict
```

Use `legacy` only when you are checking compatibility behavior for older direct
API flows:

```bash
uv run dfcc conformance run --suite legacy
```

The strict suite is the quickest regression check for the safety boundary:
raw evidence, stale embedded source, synthetic trust, missing manifest digest,
and unbound proof refs must not become authority.

## How To Navigate The Detailed Docs

- [Architecture](architecture.md) explains the system as layers.
- [Agent Usage](agent-usage.md) explains how an agent should branch on
  outcomes.
- [Protocol Mapping](protocol-mapping.md) is the formal audit table from paper
  terms to implementation names.
- [OpenAPI](openapi.yaml) describes the schema surface for tool integrations.
