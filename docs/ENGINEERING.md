# Rootwell engineering workflow

This is the repository-level contract for every change. Rootwell follows a
signed, reviewable, evidence-based delivery model while remaining a fully
separate repository from Porch.

## Priorities

The order is fixed:

1. security;
2. correctness;
3. privacy;
4. recoverability;
5. usability;
6. feature velocity.

A feature that violates a higher priority does not ship to improve a lower
one.

## Definition of done

"It runs" is not evidence. A security-relevant change is complete only when:

- its trust boundary and failure modes are understood;
- success, refusal, and malformed-input paths are tested;
- the implementation is deliberately sabotaged in both directions and the
  appropriate test fails each time;
- secret leakage, overwrite, permission, and network behavior are tested when
  relevant;
- race, static-analysis, vulnerability, and supported-platform checks pass;
- documentation says what is guaranteed and what is not;
- the evidence is recorded so an external auditor can reproduce the result
  from the repository.

Tests must verify externally observable behavior and security invariants, not
merely mirror implementation details.

## Git workflow

1. Start from an up-to-date `main`.
2. Create and verify a purpose-specific branch.
3. Inspect the worktree and index before staging.
4. Stage explicit paths; never use `git add -A`.
5. Run the relevant local gates.
6. Create a signed commit whose message explains the reason for the change.
7. Open a pull request.
8. Wait for every required check; resolve failures and review threads.
9. The implementing maintainer performs and records a separate adversarial
   self-review of the final diff, tests, and security boundaries. This is not
   an independent review. Obtain any approvals actually required by the
   repository ruleset; never bypass them.
10. Merge with a merge commit. Do not squash, rebase, auto-merge, or bypass.

## Solo-maintainer review and external audit

During development, a PR may merge without a second human reviewer when the
repository ruleset does not require one. CI success and a maintainer
self-review are development gates, not a claim that the change was
independently audited. PR notes must identify residual risks and the tests run.

Before the first public release, arrange an independent security audit of the
release candidate, for example with Claude outside the implementation session.
Provide the exact commit, threat model, security invariants, relevant diffs,
and test evidence. Track findings to resolution, rerun affected checks, and
re-audit material fixes. Do not label a release audited or publish it while
material findings remain unresolved. Repeat external review for later
security-critical releases. An AI audit can find defects but cannot guarantee
that the product is secure; seek specialist human review before production
deployment of high-risk key custody or remote-access features.

The same maintainer SSH signing identity used for Porch may sign Rootwell
commits and tags. Private signing material never enters this repository,
GitHub Actions, logs, fixtures, or documentation.

Pull-request signature verification trusts the signer list from the protected
base commit, never the list proposed by the pull request itself. A signer
rotation must therefore be authorized by a key that is already trusted; a pull
request cannot add a key and use that same key to authorize itself.

## Mandatory gates

The exact commands evolve with the implementation, but CI must cover:

- formatting and module cleanliness;
- unit, integration, negative, and regression tests;
- race detection where supported;
- vet and cross-platform type checking;
- pinned static analysis and security linting;
- known-vulnerability scanning;
- fuzz target inventory and scheduled fuzzing for parsers;
- verification that commits are signed by a published repository signer;
- reproducible release building and signature verification.

No required check may be bypassed for convenience.

The initial local gate set is:

```text
gofmt -l .
go mod tidy
go mod verify
go vet ./...
go test -shuffle=on ./...
go build -trimpath ./...
staticcheck ./...
gosec -severity medium -confidence medium ./...
govulncheck ./...
actionlint
```

CI additionally runs the race detector on Linux and vets Linux, macOS, and
Windows builds. Tool versions are pinned in `.github/workflows/ci.yml`; local
runs use those same versions.

## Cryptographic code

- Do not invent cryptographic primitives, ASN.1 encoders, or password-based
  encryption schemes.
- Prefer mature standard-library functionality where it is sufficient.
- A third-party dependency requires a written review of maintenance,
  vulnerabilities, transitive dependencies, license, and parser limits.
- Test fixtures contain generated, non-production material only.
- Private data must not appear in normal output, error strings, logs, crash
  reports, golden files, or CI artifacts.
- Network activity is denied by default for the Workbench and must be explicit
  for future connector commands.

## Relationship with Porch

Rootwell may eventually consume a documented, versioned Porch CLI or JSON
contract for independent post-deployment verification. It does not copy Porch
source, share a working tree, or mutate Porch configuration. Changes to either
product are reviewed and released independently.
