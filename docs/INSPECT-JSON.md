# X.509 inspection JSON contract

`rootwell inspect --json <file>` emits one UTF-8 JSON document followed by one
newline. The initial schema identifier is `rootwell.inspect.x509.v1`.

Schema versions are compatibility boundaries. Fields are not removed, renamed,
or assigned a different meaning within a version. An incompatible change
requires a new schema identifier and an explicit migration note.

## Top-level fields

| Field | Meaning |
|---|---|
| `schema_version` | Exact schema identifier |
| `object_type` | Always `x509-certificate` |
| `encoding` | Parsed input container: `pem` or `der` |
| `subject`, `issuer`, `serial` | Certificate identity metadata |
| `validity` | RFC 3339 `not_before` and `not_after` values; not a trust verdict |
| `public_key` | Algorithm, bit size when known, and curve name when applicable |
| `signature_algorithm` | Algorithm declared by the certificate |
| `basic_constraints` | Presence, CA flag, and nullable path-length constraint |
| `key_usage` | Stable Rootwell names for key-usage bits |
| `extended_key_usage` | Stable Rootwell names for recognized extended usages |
| `unknown_extended_key_usage` | Unrecognized extended-usage object identifiers |
| `subject_key_id`, `authority_key_id` | Uppercase colon-separated identifiers |
| `subject_alternative_names` | DNS, email, IP, and URI arrays |
| `critical_extensions` | Object identifiers marked critical |
| `unhandled_critical_extensions` | Critical identifiers Go did not process fully |
| `fingerprints.sha256` | SHA-256 over the exact parsed DER certificate |

Repeated fields are always JSON arrays, including when empty. Optional scalar
state uses an explicit empty string, zero, `false`, or `null` according to the
field type; fields are not conditionally omitted.

## Security properties and non-claims

- The schema has no raw certificate, private-key, passphrase, file-path, or
  arbitrary debug field.
- Output is ASCII-escaped without changing decoded JSON string values. Unicode
  formatting controls cannot be emitted directly to a terminal. Invalid UTF-8
  metadata fails closed instead of being silently replaced.
- Both human and JSON views are derived from the same bounded parsed result.
- Times reproduce certificate metadata. They do not state that the certificate
  is currently valid.
- Critical and unhandled extensions are observations, not acceptance.
- Parsing success is not chain, signature, hostname, revocation, or trust
  verification.
