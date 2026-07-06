# Security Policy

Future Claim Certifier treats every protocol artifact as untrusted input. The
package validates artifacts, resolves references, and emits typed blockers
instead of executing artifact payloads.

## Supported Versions

Security fixes target the latest released minor version. Before a public
release, fixes target `main`.

## Reporting Vulnerabilities

Report vulnerabilities privately through GitHub Security Advisories when the
repository is available. If that is not available, contact the maintainer
privately before opening a public issue.

Do not include exploit details, private keys, tokens, or sensitive artifacts in
public issues.

## Security Model

DFCC is a protocol engine, not a sandbox. Consumers should keep these properties
intact:

- validate schema, profile, and canonicalization before authority emission;
- verify digest identity for every referenced artifact;
- preserve reason references for non-allowing outcomes;
- treat raw evidence as audit-only unless admission succeeds;
- treat direct dictionary/dataclass authority inputs as synthetic trust unless
  `allow_synthetic_trust=True` is deliberately used for compatibility;
- require accepted checker evidence for proof-dependent decisions;
- use offline or allow-listed retrieval policies for high-integrity runs. The
  default engine does not perform network artifact retrieval;
- keep large solvers outside the trusted computing base when possible and check
  their proof objects independently.

This package does not execute code contained in artifacts. It parses JSON-like
data, validates schemas, computes canonical digests, and checks protocol
records.

## Threats To Watch

- Digest mismatch or stale artifact replay.
- Missing proof references being treated as accepted evidence.
- Conflicting lifecycle traces without a confluence proof.
- Operational declarations being trusted without measurement, representation,
  completion, adjudication, adequacy, and agreement evidence.
- Local paths, secrets, or generated files entering published archives.
- Long-lived package publishing tokens in CI.
- Unpinned GitHub Actions or release archives that include local paths.

## Release Security Checks

Before publishing, run the commands in [docs/release-checklist.md](docs/release-checklist.md):

- static checks and tests;
- bandit and pip-audit;
- primary and legacy conformance suites;
- local path and secret scans;
- wheel and source distribution archive inspection;
- Trusted Publishing workflow verification.
- GitHub Actions SHA pinning and CODEOWNERS review coverage.

PyPI publishing uses GitHub Actions Trusted Publishing. The release workflow
must not contain PyPI usernames, passwords, or API tokens.
