# ADR 0091: Renew a certificate by hand, with its new key kept in Rootwell

## Status

Accepted on 27 November 2026. It replaces the Request page's new key that
left as a password-locked file in a ZIP. It moves renewal through ACME
(Phase 3c) and delivery to servers (Phase 3d) after the first release.

## Context

Most company certificates come from a commercial provider (DigiCert,
Sectigo, GlobalSign) or from the company's own certificate authority, such
as Microsoft AD CS. Many of these have no ACME, or charge for it. They are
renewed by hand: make a request (CSR), send it to the provider, and install
what comes back.

Rootwell already made the request, but the person then carried everything:

- the new key came out of the browser in a ZIP, locked with a password the
  person had to keep;
- when the certificate arrived, they added it and the key in Certificates,
  typing that password again;
- the old certificate stayed beside the new one, with the places it is used
  and its owner, and had to be cleaned up by hand.

On 27 November 2026 the owner decided to finish the certificate work, with
renewals and alerts, before the first release, and to build ACME and
delivery slowly after it, since they touch DNS tokens and live servers.

## Decision

**A request keeps its key in Rootwell.** On the Request page, a new key
(ECDSA P-256 or RSA 2048) is made by `rootwelld` with Go's standard library
and `crypto/rand`, by `csrworkbench.GenerateKept`, which checks names and
subject exactly as the browser's request maker does. The key goes at once
into a sealed vault record of its own (`certificate-request-key`), beside the
request (`certificate-request`), both indexed by an HMAC of the key's public
fingerprint (C107). The key is never sent to the browser. The page gets the
request, which is public, to download or copy. At most 50 requests wait. A
request made with the person's own key is still signed in the browser, and
only the request comes out.

**The pages keep files and the network apart.** `request.js` reads key files
and makes no request. `request-keep.js` sends only the names and organization
details a person typed, checked for shape, to `/api/requests/create`, and
reads no file.

**Finishing.** When a certificate is saved whose public key is a waiting
request's, the request's key is checked against the certificate like a key
the person chose, and saved with it. The request and its key record are
deleted in the same write. A key sent with the certificate is set aside then:
it can only be the same key. The Add dialog says so before saving ("Key from
your request").

**Renew.** A certificate's sheet has Renew. It makes a request with the
certificate's DNS names and IP addresses, its common name when that is one of
them, and the organization, locality, province and country of its subject.
Organizational units are left out: public providers no longer accept them. A
new key is always made; the old key is never reused. One renewal may wait per
certificate, and none for a replaced certificate or one that names nothing,
such as a root.

**Taking the place.** A finished renewal takes the place of the certificate
it renews: it keeps the places the older one is used, adds its own, keeps the
older one's owner when it has none, and the older one is marked replaced,
with the date. When the older one was deleted or replaced meanwhile, nothing
is replaced. End dates are not compared: certificates last shorter every
year, so an early renewal may end before the one it renews, and it is still
the one the person asked for. Any other newer certificate may
take an older one's place when the person keeps the box ticked in Add. Then
the older one must be saved, not replaced, not an authority, name at least
one DNS name or address, all of which the newer one covers, and end before
it. The check offers the latest-ending such certificate; saving checks again.

**Replaced certificates** keep their record and key. They are left out of the
counts and the main list, and shown under a Replaced tile. Deleting the newer
one makes the older one current again. Alerts (ADR 0092) skip them.

**Giving up a request** deletes its key, so it asks first and needs a fresh
code, like deleting a certificate with a key (C111).

**Bookkeeping only.** "Replaced" is the person's record. Rootwell does not
know what a server serves; Website check, and later watched websites, tell.

## Consequences

- A new key exists only in the vault until the person downloads it, after a
  fresh code and locked with a password (C111).
- A live host compromise reveals waiting keys, as it reveals saved keys
  (C107). A stolen database or backup does not.
- The Request page no longer gives a key file. Someone who wants the key
  elsewhere downloads it from the certificate once it arrives.
- Making an RSA key takes the server a moment, so it shares the one slot
  that password checks use.
- Not covered: keys reused across renewals, organizational units, and key
  types beyond the five `rootwelld` accepts (the pages offer two).

## Evidence

`TestARequestKeepsItsKeyUntilItsCertificateFinishesIt`,
`TestARenewalTakesTheOlderCertificatesPlace`,
`TestAnEarlyRenewalThatEndsSoonerStillTakesThePlace`,
`TestAChosenReplacementMustCoverTheNamesAndLastLonger`,
`TestARequestNeedsItsOwnKeyAndGivingItUpDeletesTheKey`,
`TestARequestRecordIsReadStrictly`, `TestGenerateKeptChecksLikeTheBrowser`,
`TestLinuxARequestKeepsItsKeyAndItsCertificateFinishesIt`,
`TestLinuxARenewalIsMadeFromTheCertificateAndTakesItsPlace`,
`TestLinuxGivingUpARequestNeedsAFreshCode`,
`TestLinuxRequestInputIsRefused`,
`TestPagesSeparateFileAndNetworkCapabilities`,
`scripts/test-certificates.mjs` and `scripts/test-request.mjs`.
