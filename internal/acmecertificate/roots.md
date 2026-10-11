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
