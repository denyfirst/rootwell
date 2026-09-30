# ADR 0031: Bounded public inspection of a modern PFX

**Status:** accepted for the offline development CLI, not production custody

**Date:** 2026-09-29

## Decision

`rootwell pfx-inspect --input <file>` reads one local PFX (at most 1 MiB) and
asks for its password on a local terminal. It shows only public certificate
metadata: the one non-CA certificate whose public key matches the contained
private key, plus other certificate objects in file order. The private key,
password, PFX bytes, and bag attributes are never output or saved. Additional
certificates are called *included*, not trusted or a verified chain.

The first reader deliberately accepts only a DER, MAC-authenticated
Modern2023-shaped envelope: exactly one encrypted certificate safe and one
shrouded-key safe, SHA-256 MAC, PBES2/PBKDF2-HMAC-SHA-256/AES-256-CBC for
certificate and key encryption. The three visible envelope KDF iteration
counts must be in 1..250,000, salts and IVs are bounded, and those limits are
checked before any password-based decode. The one-shot CLI also has a 10-second
inspection deadline. This includes Rootwell-created PFX and may include
compatible third-party files; it does **not** promise broad vendor PFX import.
Legacy, passwordless, different safe layouts, and unsupported profiles fail
with a short explanation rather than an unsafe fallback.

The pinned SSLMate decoder's `DecodeChain` assumes the first certificate is
the leaf and can ignore unknown safe-bag types. That is insufficient for an
honest "what is inside" screen. For this first public-only summary, the
bounded reader uses `ToPEM` strictly to enumerate known bag types, immediately
consumes its in-memory blocks, and never emits the deprecated PEM form (which
mislabels raw RSA/EC key bytes). It rejects multiple keys, duplicate
certificates, no matching certificate, or more than 16 certificates. The
matching certificate is identified by public-key equivalence, not bag order.
Unsupported attributes/bags fail rather than being silently treated as absent.

## Boundaries and remaining risk

This is not public certificate extraction, PFX conversion, key export,
storage, TLS verification, hostname checking, revocation, or a statement
about a live server. No browser/server PFX path is opened. The CLI remains
offline. Output uses bounded, terminal-escaped public fields and stable
diagnostics that never echo paths, passwords, or input bytes.

Later [ADR 0032](0032-fingerprint-selected-public-pfx-extraction.md) adds an
explicit, public-only extraction command without expanding the PFX profile or
authorizing private-key export.

The preflight mirrors only a small envelope grammar using Go's standard
`encoding/asn1`; SSLMate performs the actual MAC and decryption. It is not a
second PKCS#12 implementation. A malicious authenticated encrypted safe may
hide an extra shrouded key with an unbounded inner KDF that cannot be seen by
this preflight. The CLI timeout returns failure and its one-shot process exits,
but the decoder has no cancellation API; this is not a safe parser for a
long-lived server. A 1 MiB input can also contain metadata sensitive to an
organization. Go/runtime copies of decrypted key material cannot be
guaranteed erased. A compromised local user, host, terminal, or process can
still observe secrets. An independent audit remains mandatory before first
real-user release. Wider PFX compatibility requires a separate parser/work
budget and interoperability review, not a silent relaxation of this gate.

Primary dependency reference: [SSLMate PKCS#12 package documentation](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12).
