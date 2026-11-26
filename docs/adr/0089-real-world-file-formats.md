# ADR 0089: Read the files real tools write

## Status

Development, 2026-11-26. Independent release audit remains pending. Widens
the PFX profile of ADR 0031 and ADR 0087, and the PFX creation profile of
ADR 0030, for the reasons below.

## Context

A test with real files on 25 November 2026 found that common files were
refused, often with a wrong reason:

- a PFX from Windows, .NET, OpenSSL -legacy or Java (3DES or RC2 under a
  SHA-1 MAC) was refused as "That password does not open this PFX";
- a PFX without a password could not be opened;
- a P7B bundle was taken for a key, and the message named the wrong file;
- one PEM with the certificate, key and chain (HAProxy, or `openssl pkcs12
  -nodes` output with "Bag Attributes" lines), a byte order mark from
  Notepad, an EC key after an `EC PARAMETERS` block and an old OpenSSL
  encrypted key (`Proc-Type: 4,ENCRYPTED`) were refused;
- a wrong key password said only "Rootwell could not read these files";
- a PFX was recognised only by its `.pfx` or `.p12` name;
- Convert made AES-256 PFX files only, which Windows Server 2016 and older
  cannot import.

## Decision

### PFX

`pfxinspect.Preflight` now accepts, before any password is tried:

- a MAC with SHA-1, SHA-256 or SHA-512, salt 8 to 64 bytes;
- certificate and key encryption with legacy PKCS#12 3DES, 128-bit RC2 or
  40-bit RC2, or PBES2/PBKDF2 with AES-128/192/256-CBC and an HMAC-SHA-1,
  SHA-256 or SHA-512 PRF (an absent PRF is HMAC-SHA-1); salts of 8 to 64
  bytes, a 16-byte IV, a key length that matches the cipher when present,
  and ciphertext that fills whole cipher blocks;
- exactly two safes, in either order, at least one of them unencrypted and
  holding the one shrouded key; any other bag in an unencrypted safe
  (plain key, CRL, secret, nested safe, unknown) is refused;
- at most 17 bags per visible safe and 8 attributes per bag;
- every visible work factor at most 250,000 iterations, input at most 1 MiB.

This covers what Windows and .NET (key safe first, 3DES, SHA-1 MAC),
OpenSSL 3, OpenSSL -legacy and Java keytool write. The iteration cap stays:
OpenSSL writes 2048, Windows 2000 and Java at most 100,000.

The pinned SSLMate decoder still verifies the MAC and decrypts; Rootwell
implements no PKCS#12 cryptography (ADR 0030). Its strict `ToPEM` lister
still enumerates every bag after the MAC verifies, so an unknown bag inside
an encrypted safe is refused. That lister also refuses bag attributes it
cannot name, and Windows writes such attributes for a machine key and for
"Export all extended properties". When, and only when, the lister stops at
such an attribute, `DecodeChain`, which ignores attributes, reads the same
authenticated contents; it still refuses a second key and a non-X.509
certificate bag.

A PFX without a MAC is refused as one without an integrity check. An empty
password opens a PFX saved without one; the decoder tries both the empty
BMPString and the no-bytes conventions. Refusals now say why: wrong
password, not a PFX, no integrity check, unsupported protection or layout,
or contents that are not one RSA or EC key with its non-CA certificate.

Key export and reveal take the key from the same decode that matched it to
the certificate (`pfxinspect.Open`), so a PFX that lists the issuer first,
as Windows does, exports too.

Not accepted: a SHA-384 or SHA-224 MAC or PRF and PBMAC1, which the pinned
decoder does not read; one safe or three; two encrypted safes; Ed25519 keys
in a PFX; public-key integrity mode. Each is refused before the password,
as an unsupported protection or layout.

### PFX creation

Convert gains a labelled "PFX for older Windows" choice: 3DES for the
certificates and the key under a SHA-1 MAC with 2048 iterations, as OpenSSL
-legacy and Windows write it. The required 20 to 128 character password, not
the iteration count, protects the file. AES-256 with 100,000 iterations
stays the default and the first choice. Every created PFX passes the same
reader as an imported one before it is offered.

### Other files

Three small readers, each refusing what it does not understand:

- `pkcs7certs` reads a DER certs-only SignedData: version 1, no digest
  algorithms, no content, no signers, no revocation list, 1 to 64 distinct
  X.509 certificates. BER is refused.
- `legacypemkey` opens an old OpenSSL encrypted RSA or EC PEM key with
  DES-EDE3-CBC or AES-128/192/256-CBC, using EVP_BytesToKey with MD5 and one
  round, the format's own definition; bounded to 64 KiB and a 256-byte
  password. Rootwell never writes this format.
- `fileformat` says what one chosen file holds: a PFX (by its content, not
  its name), certificates, one key, or certificates with their key. It
  accepts a UTF-8 byte order mark, CRLF, and printable text between PEM
  blocks. It refuses an unknown block, a second key, a block whose base64
  or framing is broken, a stray boundary line, and EC parameters that are
  explicit or name another curve than the key's. It hands each part on in the
  strict form the rest of Rootwell already accepted.

The browser engine uses `fileformat` before its existing strict readers, in
Add, Inspect and Convert. An old-style encrypted key is opened in the
browser and reaches the server unlocked, as an unlocked key file would.

### The server

The server's accepted input does not change: strict PEM certificates, and a
strict key, unlocked or bounded PBES2 PKCS#8. It now tells a wrong key
password from a missing one: 422 with `X-Rootwell-Refusal:
key-password-wrong`.

## Why it stays safe

- Every widened parser runs on bounded input, refuses rather than skips, and
  has its own fuzz target (`FuzzPFXPreflight`, `FuzzParseCertsOnly`,
  `FuzzDecryptLegacyKey`, `FuzzSplit`).
- The visible KDF work stays capped before decoding, and the one key must be
  visible. As before, an encrypted safe could hide expensive work for a
  person who opens such a file with its password; the one-shot worker and CLI
  deadlines still bound the wait.
- Weak legacy protections are read so a person can move off them; Rootwell
  writes 3DES only when asked for older Windows, never RC2, and never the old
  PEM format.
- Nothing new reaches the server: the browser normalises, the server
  validates the same strict forms as before.
- A combined file's key is handled like a chosen key file: Add sends it to
  the server's existing key check; Inspect gives it only to the one-shot key
  check and never shows it.

## Remaining risks

- With Windows attributes the attribute-free reader is used, and it would
  skip a CRL, secret or nested bag inside an encrypted safe. Such a bag is
  not stored; the key and certificates are still checked as before.
- 3DES, RC2 and a SHA-1 MAC are weak by today's measure; Rootwell reads them
  and tells nobody otherwise. A strong password is what protects such a file.
- SHA-384 PFX files stay unreadable until the pinned decoder reads them.
- No real Windows Server 2016 import of the older Windows PFX was tested in
  this change; the profile is the one OpenSSL -legacy writes.
