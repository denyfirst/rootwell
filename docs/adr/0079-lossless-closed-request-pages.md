# ADR 0079 — Lossless retained pages for closed certificate requests

Date: 2026-10-29. Independent capacity increment in the authorised first stage.

The active list's 32 closed requests is a deliberate bound, not permission to
discard an older renewal anchor, completion, ownership receipt or encrypted key.
Allow an explicit local repack of 16–32 closed requests into one of four retained
pages, preserving their exact encrypted records. The active bound stays 32;
maximum total retained scopes is 160. All page and active records participate in
the same authenticated chronological/unique-URL/renewal-anchor validation.
A separately authenticated retained-count field rejects missing/dropped pages;
new order and renewal intent refuse a full active closure list before I/O.
Historical scopes have no network/replay/key-export authority. Pair deletion
must find and update its existing tombstone even in a retained page. Pages do
not free disk bytes, recycle generations, reset counters or resolve pending DNS.

Only an already closed request can move; active/unknown scopes, their pending
reservations, account, DNS credential and other ciphertext stay untouched. A
fresh password, exact generation, separate `lossless-request-archive` consent
and backup/compatible-binary acknowledgement precede the Linux writer transaction.
The result must authenticate wholly before atomic publication. Older binaries
reject images containing the new field; use a matched binary and full backup.
Capacity, clock, private-file, current permission and full recovery fences stay.

The existing optional storage-maintenance details show active/retained usage,
one local archive action and its limits. No extra product menu or duplicate
certificate library. Manual DNS status moves to v9 so its total closed count may
range to 160; unchanged fields do not become extra admission authority. Synthetic
preview cannot accept secrets or mutate. Four pages remain a finite bound; there
is no silent pruning or claim of infinite retention.

Required evidence: max-active repack and subsequent closure; unchanged nested
ciphertext; archival lineage/superseded provenance and pair tombstone updates;
stale/clock/malformed/reordered/duplicate/over-cap refusal; pending reservations
and active unknown ownership preservation; actual Linux lock/full recovery/API;
strict scope/fresh authentication, native refusal, UI stale/hidden/late refusal,
two-way compiling sabotage, signed commits and all final-head CI/self-review.
Real provider tests, full renewal, production isolation and independent release
audit remain the following authorised stages. Porch is outside this work.

Two-way compiling sabotage (2026-10-29): disabling retained-count consistency
made `TestRequestArchiveRefusesStaleClockMalformedOrDroppedPages` fail with
`corrupt archive exposed partial status`; inverting admission made
`TestRequestArchiveFullActiveLosslessAndNextClosure` refuse its valid repack.
Restoring both guards passed both suites. The complete 160-scope capacity test
uses real model transitions and confirms the final bound without pruning.
Additional tests preserve unknown active order and reserved outcomes, recover an
archived pair's source/provenance and update only its existing deletion tombstone.
The private synthetic Linux fixture has a native current-clock round-trip test;
it adds no runtime trust, clock or provider override. Linux execution remains CI
evidence until that platform's actual tests complete.
