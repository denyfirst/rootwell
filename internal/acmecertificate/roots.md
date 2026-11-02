# Staging-only independent trust — not ordinary TLS trust

Reviewed 2026-10-12 from the four **self-signed** PEM links on the official
[Let's Encrypt staging documentation](https://letsencrypt.org/docs/staging-environment/).
Read-only HTTPS retrieval, redirects disabled; SHA-256 over decoded DER below.
Go tests independently reparse, verify self-signatures, policy and exact hashes.
This is HTTPS/source review, not an independent out-of-band trust ceremony.

| Root | Official source | DER SHA-256 |
| --- | --- | --- |
| Pretend Pear X1 | https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x1.pem | E70570A989F8565AABDF7CAE27ABD1621872D6A3F811E3FEF27E3DBA02912198 |
| Bogus Broccoli X2 | https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x2.pem | 9B2A339FE6A3E85585C4CD75536CB8C1CF7CD603B9A64BEC2521858AE48DA85D |
| Yearning Yucca Root YE | https://letsencrypt.org/certs/staging/gen-y/root-ye.pem | B59BFC0BA52DAF849853B7324A91E82F031DB3397F35644157352CDE6384B56C |
| Yonder Yam Root YR | https://letsencrypt.org/certs/staging/gen-y/root-yr.pem | EF115FB59E040FF39D15FD8F3EF54063C704321D83CB081213272F77D3091672 |

Public certificates only. No private keys or account identity. Intermediates
are intentionally not pinned. These roots are not audited/ordinary-browser
trust anchors: never add them to system/browser TLS stores. This private
offline checker uses them only for staging receipt acceptance. A changed or
missing root refuses; rotation needs a reviewed signed code/asset change, not
automatic discovery or a response-supplied root. No AIA/OCSP/CRL request is made.
The checker does not establish revocation, CT, order ownership or deployment.

## Separate production receipt trust (2026-10-29)

`production-roots.pem` contains only the self-signed **ISRG Root X1** and
**ISRG Root X2** from the official [chains-of-trust page](https://letsencrypt.org/certificates/),
reviewed 2026-10-29 (page updated 2026-07-08). HTTPS read, redirects disabled;
Node independently checked CA identity/self-signatures before the asset was
saved. Go reparses, checks policy/self-signatures and exact DER pins. This is
source/HTTPS review, not an independent out-of-band trust ceremony.

| Root | Official source | DER SHA-256 |
| --- | --- | --- |
| ISRG Root X1 | https://letsencrypt.org/certs/isrgrootx1.pem | 96BCEC06264976F37460779ACF28C5A7CFE8A3C0AAE11A8FFCEE05C0BDDF08C6 |
| ISRG Root X2 | https://letsencrypt.org/certs/isrg-root-x2.pem | 69729B8E15A86EFC177A57AFB7171DFC64ADD28C2FCA8CF1507E34453CCB1470 |

These roots never join the staging pool or OS/browser trust. Cross-signed
intermediates still need the full exact path to an independent pinned root.
The separate offline `CheckProduction` reuses every key/CSR/name/usage/expiry/
bounded-chain check and returns `TestOnly: false` only after success. It cannot
enroll, connect, promote a saved test result, change custody profile or deploy.
Production network/custody/UI integration and real provider tests remain a
separate gate. Rejection of synthetic roots is tested through both fixed entries;
positive synthetic path tests use an unexported test-only root seam.
