# ADR 0020: Authenticated complete inventory image before persistence

Rootwell first models a public certificate inventory in memory and has a
record-level AES-256-GCM codec. Neither establishes what the complete durable
set of records is, or what generation a reader should expect. We introduce a
bounded, canonical image codec with an HMAC-SHA-256 manifest keyed by the
installation data key. Each public record is still individually encrypted
and bound to its installation, SHA-256 certificate identity, and generation.
The complete image is validated before any records are returned.

The image-local counter begins at one and advances on every successful import.
It is capped at one million imports, well below the random-nonce GCM per-key
message limit, even for the maximum 500 records. The image discloses record
count, certificate digests, generations, and ciphertext sizes; owner, location,
and DER remain encrypted. It is not yet written to disk.

A single atomic file replacement is the intended first persistence strategy,
to avoid partial manifest/record commits. This design cannot distinguish a
fully rolled-back authenticated file from a current one without an external
trusted generation anchor. Backup and restore will explicitly retain that
limitation. Linux private-directory checks, single-writer coordination,
crash/disk fault tests, full backup, and a fresh restore drill are mandatory
before any user-facing save operation. Native Windows storage needs its own
ACL design; mode bits are insufficient.
