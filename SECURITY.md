# Security policy

Rootwell will process certificates and, in later phases, private cryptographic
material. Security reports are treated as product work, not support noise.

## Reporting

Do not open a public issue for a suspected vulnerability or include secrets,
private keys, production certificates, credentials, or customer data in a
report. Use the private security-reporting channel published on the Rootwell
GitHub repository once it is available.

Until that repository channel exists, do not send production secret material.
A minimal report may describe the affected command, version, expected security
boundary, observed behavior, and a reproduction using generated test material.

## Scope

Security-relevant findings include:

- disclosure of private material through output, logs, errors, artifacts, or
  temporary files;
- unintended network access by local-only Workbench commands;
- unsafe overwrite, file-permission, path, or symlink behavior;
- parser crashes, resource exhaustion, or acceptance of malformed input;
- incorrect key/certificate matching or chain verification;
- authentication, authorization, approval, or tenant-boundary bypasses;
- agent command expansion beyond documented capabilities;
- signature, update, build, or release supply-chain failures.

## Test data

Use newly generated, non-production fixtures. If a proof requires sensitive
material, agree on a protected transfer method before sending it.

## Disclosure

We aim to acknowledge a complete report, reproduce it, communicate impact and
mitigation, and coordinate disclosure after a verified fix is available. No
timeline is promised before severity and reproducibility are established.
