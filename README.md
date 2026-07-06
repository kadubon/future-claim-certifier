# Future Claim Certifier

Future Claim Certifier is a Python implementation of Dynamic Future-Claim
Certification (DFCC). It checks whether a time-bound claim about a future state
can be used as authority, and it explains why the answer is allow, deny,
unknown, expired, blocked, or conflicting.

The project is designed for software agents, auditors, and protocol engineers
who need decisions that can be replayed later from the same files. Every
important input is a canonical artifact with a digest, schema, reason path, and
typed outcome.

Paper: Takahashi, K. (2026). *Dynamic Future-Claim Certification: A Replayable
Authority Validation Protocol with Canonical Artifacts*. Zenodo.
https://doi.org/10.5281/zenodo.21199529

## What It Does

DFCC separates three questions that are often mixed together:

- What was certified at issue time?
- Is the certificate still active at use time?
- Is the requested use allowed for this context?

The package implements the protocol layer:

- canonical JSON and digest identity;
- artifact bundles and reference resolution;
- schema/profile validation;
- accepted evidence and audit-only raw evidence;
- bounded certificate issuance;
- lifecycle/status replay;
- represented and operational authority checks;
- golden conformance cases.

It is not a general solver. The bundled backend is an exact finite-state
reference backend for small examples and tests. Larger solvers, simulators, or
proof engines can be connected behind the checker interfaces.

## Install

For users:

```bash
python -m pip install future-claim-certifier
dfcc conformance run --suite primary
```

For local development:

```bash
uv sync --all-groups
uv run dfcc conformance run --suite primary
```

Python 3.11 or newer is supported. The import package is `dfcc`; the command
line tool is `dfcc`.

## Five-Minute CLI Flow

Create a certificate from the safe-temperature example:

```bash
uv run dfcc certify examples/safe_temperature/spec.json --out issue.json
```

Check whether a represented use is allowed at status time:

```bash
uv run dfcc check \
  issue.json \
  examples/safe_temperature/proposed_use.json \
  examples/safe_temperature/status_context.json \
  --out status-view.json
```

Run full artifact-bundle replay:

```bash
uv run dfcc validate-bundle artifact-bundle.json --full-replay
```

Replay lifecycle/status data directly from a bundle:

```bash
uv run dfcc replay-status --bundle artifact-bundle.json
```

List and export schemas:

```bash
uv run dfcc schema list
uv run dfcc schema export issue-certificate.schema.json --out issue-schema.json
```

Run packaged conformance suites:

```bash
uv run dfcc conformance run --suite primary
uv run dfcc conformance run --suite legacy
```

## Python Example

```python
from dfcc import check_authority
from dfcc.certificate import certify_claim, certify_claim_from_artifact_bundle

certificate = certify_claim(claim, bundle, anchor, time_basis)
view = check_authority(certificate, proposed_use, status_context)

outcome = view.authority_outcome
if outcome.code == "assert" and not outcome.blocking_set:
    use_claim_as_represented_authority()
```

For strict artifact-bundle issuance, use:

```python
certificate = certify_claim_from_artifact_bundle(artifact_bundle)
```

The strict path uses accepted clauses or explicit trust assumptions. Raw
evidence is audit data only and cannot silently change the certified semantics.

## Reading Outcomes

DFCC is conservative. Missing or conflicting evidence is never upgraded into an
allowing result.

Common results:

- `assert`: the represented claim is currently usable as true for the requested
  represented use.
- `deny`: the represented claim is currently usable as false for the requested
  represented use.
- `accept`: the operational target is allowed after observation, completion,
  fiber, adjudication, adequacy, and policy checks.
- `reject`: the operational target is rejected by those checks.
- `unknown`: more accepted evidence or proof material is needed.
- `expired`: the status time is outside the certificate validity window.
- `out_of_frame`: the requested use is outside the certified frame.
- `conflict`: artifacts, lifecycle traces, or proof records disagree.
- `policy_block`: the protocol result exists, but policy does not allow use.

For non-allowing outcomes, inspect `blocking_records`, `failure_records`, and
typed `reason_ref_records`. They identify the artifact digest and JSON Pointer
path that caused the decision.

## Documentation

- [Docs index](docs/index.md): start here for learning paths.
- [Architecture](docs/architecture.md): main concepts and trust boundaries.
- [Agent usage](docs/agent-usage.md): safe use by autonomous agents.
- [Protocol mapping](docs/protocol-mapping.md): paper definitions mapped to API,
  schemas, failure codes, and conformance cases.
- [Release checklist](docs/release-checklist.md): pre-publish audit steps.
- [Security policy](SECURITY.md): security model and reporting.
- [Contributing](CONTRIBUTING.md): local development commands.

## Release And Quality Gates

The repository CI runs:

- ruff format and lint;
- mypy strict type checking;
- pytest with coverage gate at 90% or higher;
- bandit;
- pip-audit;
- primary and legacy conformance suites;
- package build and distribution metadata checks.

PyPI publishing uses GitHub Actions Trusted Publishing. No long-lived PyPI API
token is required.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
