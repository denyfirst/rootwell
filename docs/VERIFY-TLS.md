# Offline TLS server verification contract

`rootwell verify` answers one narrow question: can this leaf certificate build
a valid TLS server chain, for this hostname and instant, to one of these
explicitly trusted roots under Rootwell's algorithm policy?

```text
rootwell verify server.pem \
  --trust-bundle roots.pem \
  --intermediates intermediates.pem \
  --hostname service.example.test
```

The leaf accepts exactly one PEM or DER X.509 certificate. `roots.pem` must
contain one or more self-signed CA certificates. `intermediates.pem` is optional
and contains non-self-signed CA certificates only. Each bundle is at most 16
MiB and 64 certificates. Duplicate, mixed, header-bearing, and junk content is
rejected.

## What a passed result proves

- the leaf is not a CA;
- its DNS identity matches the requested hostname;
- its verified chain reaches an explicitly supplied trust anchor;
- the chain is valid at the reported UTC instant;
- TLS server usage and X.509 path constraints pass;
- all chain members satisfy Rootwell's public-key and signature policy.

The hostname input is printable ASCII without wildcards. Internationalized
names must be supplied in their canonical ASCII/Punycode representation.

## What it does not prove

- revocation status through OCSP or CRLs;
- Certificate Transparency inclusion;
- that any remote server currently presents this certificate;
- that the operator possesses the corresponding private key;
- that the certificate is suitable for a profile other than TLS server auth.

No system trust store is used and no network connection is made. These are
deliberate guarantees, not missing automatic behavior. Live endpoint checking
will remain a separate operation so a local file verdict cannot be confused
with deployment evidence.

## Output and failures

Success is exit code `0` and requested evidence is written to stdout. Usage
errors return `2`; read or verification failures return `1` on stderr. Failure
messages classify the problem without repeating paths, hostnames, certificate
names, or parser-controlled strings. Successful output always includes:

```text
verification: passed
profile: tls-server
revocation: not-checked
network: disabled
```
