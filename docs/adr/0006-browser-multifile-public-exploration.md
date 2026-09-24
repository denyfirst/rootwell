# ADR 0006: Bounded multi-file public exploration

## Status

Accepted for local Workbench development; not an independent security audit.

## Context

Certificate issuers often deliver a leaf and a bundle as separate files. A
one-file explorer makes users repeat inspection without showing the complete
set they received. Joining arbitrary files into one byte stream is unsafe:
DER and PEM have different framing, duplicates may occur between files, and
there is no reason to infer that a supplied CA certificate is trusted.

## Decision

Explore accepts 1–8 selected public files. Each file is read only after the
user presses Explore and is passed separately through the existing strict Go
public-bundle parser. The browser rejects the entire collection if any file
fails, if the combined selected bytes exceed 16 MiB, if the total certificate
count exceeds 64, if certificate metadata text exceeds 1 MiB, or if a full
SHA-256 fingerprint occurs twice across files. No partial cards are shown.

Each card retains a reference to its original selected file for the existing
public-only export flow. Export re-reads that file, re-parses it, and selects
by the full fingerprint. Changing the selection invalidates the old cards.
Source filenames appear only as DOM text and never determine parsing, trust,
or generated download names. Raw input buffers are cleared best-effort after
each file. The existing same-origin, no-upload WebAssembly boundary remains.

## Non-claims and follow-up

This is a metadata collection, not a concatenated certificate bundle or a
verified chain. It does not classify leaf/intermediate/root roles, promote any
CA certificate to a trust anchor, consult system roots, or perform Verify.
Simple Verify still requires a separately selected trust source, hostname,
and the same reviewed verification policy as Advanced. Browser and OS memory
erasure cannot be guaranteed.
