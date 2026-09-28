# ADR 0029: Stage secret-bearing conversion outside the browser

**Status:** accepted as an implementation boundary; Linux offline PFX creation is the first enabled increment

**Date:** 2026-09-28

## Context

The Workbench now has one public Inspect entry and a separate, easy-to-find
Convert view. Its browser parser rejects PFX and private keys. A PFX can contain
an exportable private key, certificates, and attributes; it is not just another
certificate encoding. The instance password protects the self-hosted inventory,
not an uploaded PFX or its export password.

## Decision

The first secret-bearing conversion increment, if its gates pass, will be an
**offline CLI operation** in the separate `rootwell` process. It will not call
the inventory daemon, browser gateway, Porch, or a network service. No key is
silently saved to the vault. Browser/server conversion remains disabled until
a separate boundary review and implementation-specific internal tests. The
independent audit remains a release gate before real users, not a development
gate that stops later capability work.

The implementation sequence is:

1. Decide and review the PKCS#12 library version, transitive code, license,
   security advisories, and exact parser/encoder profiles. Pin it only when
   the review is complete. Do not write our own PKCS#12, password encryption,
   or ASN.1 container implementation.
2. Provide a local, public-only CLI certificate conversion path and its safe
   file-output primitive. This cannot accept a key or PFX and must not be
   repurposed for secret output without the controls below.
3. Add a separate opt-in `create PFX` operation: one explicitly supplied leaf,
   one explicitly supplied unencrypted key, and explicitly supplied public CA
   certificates. Validate the leaf/key match, reject ambiguous/duplicate/
   unrelated material, and distinguish "included chain" from "trusted chain".
   Require a fresh, nonempty output password from a trusted interactive
   terminal. No password in argv, URL, environment, logs, or JSON.
4. Add PFX inspection and public certificate extraction only after bounded
   decode and MAC/authentication-negative tests. Key extraction is another
   increment: a deliberate, separately named action with explicit warning,
   encrypted PKCS#8 output by default, and no stdout/raw-JSON key output.
5. Consider one browser Convert workflow for these operations only after a
   browser-specific threat model, CSP/memory/download/retention tests, a
   trusted-host requirement. The independent audit gate remains before the
   first release. The UI may share navigation with public Convert, not its
   permissive data path.

Every secret output uses an explicit destination, create-new/no-overwrite
semantics, platform-specific private permissions, atomic completion and
read-back validation. No output is reported successful after a failed write,
close, sync, or validation. A symlink, unexpected existing file, or unsafe
directory fails closed. The exact Windows and Linux contracts must be tested
before enabling each platform; an unsupported platform must refuse explicitly.

Conversion proves only container parsing, leaf/key correspondence, and
post-write equivalence. It does not prove CA trust, revocation, hostname,
deployment, or possession by a remote server. If an input PFX contains an
unsupported bag, multiple keys, or attributes we cannot preserve or safely
explain, conversion fails rather than silently discarding them.

## Why this ordering

The offline CLI has a smaller attack surface and can make output file handling
explicit. A browser has additional risks from origin compromise, extensions,
download handling, and uncontrolled memory copies; a self-hosted server adds
transit and multi-process custody. Reusing the inventory login password as a
PFX password would couple unrelated security boundaries and is prohibited.

## Non-goals and remaining risks

- This ADR itself added no CLI command or dependency. ADR 0030 implements the
  first Linux offline creation increment; browser file picker, vault custody,
  and production support remain outside this decision.
- A local administrator, compromised executable, malicious browser extension,
  swap, crash dump, or backed-up output file can still disclose a key.
- Go cannot promise complete memory erasure. Buffer clearing is best effort,
  not a secure-deletion claim.
- Legacy PFX interoperability may require weak algorithms. Such a profile
  needs a separate, explicit compatibility decision and must not become the
  default.

The detailed abuse cases and release gates are in
[`../SECRET-CONVERSION-THREAT-MODEL.md`](../SECRET-CONVERSION-THREAT-MODEL.md).
