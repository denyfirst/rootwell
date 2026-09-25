# ADR 0010: Export only a re-verified public server chain

## Status

Accepted for local Workbench development; not an independent security audit.

## Decision

The Verify panel may offer a public PEM server-chain download only after an
explicit-trust TLS-server success. The browser holds only a snapshot of the
displayed chain fingerprints, selected public File objects, hostname, mode,
and evaluation time. It does not retain certificate bytes for export.

When clicked, the current files are read again under the 16 MiB combined
limit. The Go WebAssembly core re-runs the same Simple or Advanced verifier
with the separately selected trust file. The complete ordered verified path,
including its trust anchor, must equal the previously displayed fingerprint
snapshot. Otherwise the operation returns no bytes and invalidates the old
Verified UI state. A changed input selection invalidates that state before a
download can be requested.

The output is canonical PEM containing the verified leaf followed by its
verified intermediates, in path order. The independently supplied trust root
is excluded. Neither private key nor PFX is accepted. The output is bounded
to 4 MiB, re-parsed, and compared byte-for-byte to the selected public source
certificates. The browser also re-parses the returned PEM and checks its
ordered fingerprints before requesting a browser-managed download. A random
filename avoids certificate-derived names; Rootwell does not write directly
to disk or promise browser/OS no-overwrite behavior.

## Non-claims

The file represents the verified path **at the displayed evaluation time**,
which Advanced users may set explicitly. It is not evidence that the chain is
valid now, installed on a server, unrevoked, CT-logged, or paired with a
private key. The tool does not install the demo root in any trust store.
