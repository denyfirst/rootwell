# Rootwell Workbench threat model

**Scope:** local Workbench CLI through v0.1

**Last reviewed:** 2026-09-21

This document covers the process that reads local certificate and key material,
performs an explicitly requested operation, and writes a result to a caller-
selected destination. The future server, agent, browser gateway, CA connectors,
and vault each require a separate threat model before implementation.

## Security objective

Rootwell must let an operator inspect and transform cryptographic material
without disclosing it, silently changing it, weakening it, or claiming a trust
decision it did not actually prove.

## Data classification

| Class | Examples | Default handling |
|---|---|---|
| Secret | private keys, passphrases, recovery material, API credentials | never log or print; keep local; write only on explicit request with restrictive permissions |
| Sensitive metadata | file paths, internal hostnames, subject names, SANs, owner and inventory relationships | do not echo in errors by default; include in requested output only |
| Public cryptographic material | certificates, CSRs, public keys, fingerprints | may be displayed when requested; integrity still matters |
| Operational evidence | format verdicts, validation failures, tool version, policy version | safe structured output; must not contain secret input |

Certificate content is not assumed harmless. Internal names, identities, and
organization data can be sensitive even when a certificate is technically
public.

## Trust boundaries

```text
operator
   │ arguments, stdin, environment
   ▼
Rootwell process ───────▶ stdout/stderr
   │                         │
   │ bounded reads           │ secret-free diagnostics
   ▼                         ▼
local filesystem        caller or pipeline
   │
   └── explicit output path, atomic replace rules, restrictive permissions

No network boundary exists in Workbench v0.1: network access is out of scope
and therefore forbidden.
```

The following are untrusted inputs:

- every command-line token, including file names;
- file contents and claimed extensions;
- PEM labels, ASN.1 fields, certificate names, and embedded URLs;
- environment variables and current working directory;
- output directories, symlinks, and pre-existing files;
- data received through stdin;
- fixtures contributed in a pull request.

Go's standard library is trusted only within its documented contract. A parser
returning success is not by itself evidence that the object is appropriate for
the requested operation.

## Threat actors

- an attacker who supplies a malformed or adversarial file;
- a local user racing or replacing a path Rootwell is about to write;
- a malicious repository contributor attempting secret disclosure or supply-
  chain execution;
- an operator making an unsafe but plausible mistake;
- a compromised dependency, build input, release artifact, or signing account;
- a future control plane or agent that has been compromised.

An attacker with administrator/root control of the machine can read Rootwell's
memory and replace the executable. Protecting a fully compromised host is not a
claim of the Workbench. Hardware-backed and remote signing models are separate
future boundaries.

## Abuse cases and required controls

| Abuse case | Required control |
|---|---|
| A secret is placed in a file name or unknown command and reflected in an error | diagnostics describe the rule, not the supplied value; regression and fuzz tests |
| A huge or deeply nested input exhausts memory or CPU | bounded reads, explicit object-count limits, parser fuzzing, and time/resource tests before parser release |
| A file extension lies about its content | classify from bounded content; an extension may suggest but never decide a format |
| Conversion silently drops certificates, attributes, or key protection | post-conversion parse and semantic comparison; unsupported preservation fails closed |
| A private key is printed by JSON or debug output | typed output models exclude private bytes; leak tests search every output channel |
| An existing file is replaced unexpectedly | create-new by default; overwrite requires an explicit mode and safe replacement transaction |
| A symlink redirects secret output | platform-specific path and handle validation; tests cover links and races where the OS permits |
| A passphrase appears in process listings or shell history | never accept passphrases as command-line values or URLs |
| Chain verification trusts the host implicitly | v0.1 requires an explicit trust bundle unless a separately named mode says otherwise |
| Parsing follows AIA, CRL, OCSP, or other embedded URLs | Workbench parsing performs no network access |
| A successful issuance is reported as successful deployment | lifecycle states keep issuance, placement, reload, health, and external verification separate |
| A pull request weakens a guard while keeping tests green | behavior tests, two-direction sabotage, signed commits, required review gates, and invariant citations |

## Fail-safe behavior

- Unknown, ambiguous, encrypted-but-unsupported, truncated, trailing, or mixed
  input fails explicitly.
- Rootwell never guesses a private-key password, trust anchor, intended target,
  or output format.
- Partial output is removed or left in a clearly named staging state; it is not
  presented as success.
- Failure output is one line where practical, secret-free, and stable enough for
  automation without exposing attacker-controlled strings.
- A write, flush, close, permission, validation, or rename failure makes the
  operation fail.

## Implemented inspection boundary

`rootwell inspect <file>` reads at most 16 MiB and accepts exactly one X.509
certificate in DER or a header-free PEM `CERTIFICATE` block. DER must consume
the complete input; PEM may have surrounding whitespace but no second block or
other trailing content. Classification comes from bounded content, never the
file extension. Certificate-derived display text is limited to 1 MiB in total
and repeated metadata fields are limited to 4,096 before output escaping.

The result is metadata only. Successful parsing does **not** mean that the
certificate is trusted, currently valid, correctly signed, suitable for a
hostname, or linked to a valid chain. Embedded AIA, CRL, OCSP, and other URLs
are displayed as escaped data when applicable and are never followed. The
production Workbench packages are tested to reject direct network,
child-process, plugin, and unsafe-code imports.

Human output and the versioned JSON view come from the same typed result, which
cannot contain private-key bytes or the input path. JSON is ASCII-escaped while
preserving decoded string values, including non-ASCII certificate names. Key
usage, Basic Constraints, identifiers, and critical extensions are reported as
observations; reporting them does not mean that Rootwell accepts their policy.

## Supply-chain boundary

- The shipped module starts with no runtime dependencies.
- Adding a dependency requires a committed decision record covering ownership,
  maintenance, vulnerability history, transitive code, license, parser limits,
  and the security benefit over the standard library.
- GitHub workflows use no third-party actions. Tools installed during CI are
  version-pinned and do not become runtime dependencies.
- Commits and tags are signed; releases will have a separate reproducibility
  and checksum-signing procedure before the first release.

## Review triggers

Review and version this model before adding any of the following:

- secret-bearing output or a parser for an object other than one X.509 certificate;
- password or interactive terminal input;
- temporary files or overwrite support;
- any network-capable command;
- a third-party runtime dependency;
- the server, database, agent, vault, browser gateway, SSH CA, or PGP support;
- a new supported operating system or filesystem security guarantee.
