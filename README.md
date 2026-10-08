# DenyFirst Rootwell

**Status:** development Workbench, loopback access gate, and Linux-only certificate library

Rootwell is a privacy-first, self-hosted workspace for X.509 certificates and
their associated private keys, with explicit match status. SSH, PGP and interactive SSH/RDP access are outside
the current product scope.

> Your private root of trust.

The first product increments are a local-first Workbench CLI and browser for
safe public-certificate inspection and verification. An experimental local
access gate protects the browser. Optional certificate/key custody is now a
separate development capability; automation and remote access remain outside
this release boundary. This is not audited or production-ready custody.

The Linux-only public-certificate inventory has an explicit self-hosted Save
page, bounded manual locations for one fingerprint without duplicate DER,
explicit correction/clearing of unverified owner notes,
explicit correction/removal of unverified location notes,
authenticated encrypted storage, and complete access+inventory backup
and fresh restore commands. A Linux-only Docker/Compose development profile
and disposable bind-volume restore drill are documented in the
[container recovery guide](docs/CONTAINER-RECOVERY-AZ.md). The separate
certificate-library route stores a certificate/bundle and optional private key;
valid mismatches require explicit acknowledgement and remain loose attachments.
The public importer still rejects secrets; neither path
makes trust/deployment claims or automatically backs itself up.
A listed location is not proof of live deployment. Native Windows storage
and independent release audit remain open gates;
see the [inventory threat model](docs/INVENTORY-THREAT-MODEL.md) and
[custody threat model](docs/CERTIFICATE-CUSTODY-THREAT-MODEL.md).

## Project doctrine

Saved public-only certificates now offer **Add private key** without re-import:
optional Check, fresh Rootwell password and Save. Existing keys cannot be
replaced; certificate/bundle/notes stay intact. **Details → Convert format**
opens only the public certificate in the existing Workbench converter. A
private key is never automatically handed off; use encrypted key download and
explicit selection for key/PFX conversion. See [ADR 0048](docs/adr/0048-saved-key-attachment-and-convert-handoff.md).

The current development increment adds an optional **Inspect → Check key
match locally** action and one **Certificates → Add a certificate** flow for
a certificate/related public bundle plus optional key. Save always checks;
an unrelated valid key requires explicit acknowledgement and stays labeled
**does not match**, never a usable pair. Included public bundle and encrypted
key-only downloads are separate; fresh authentication protects all key exports.
Multiple unrelated public imports stay under Advanced. See
[ADR 0047](docs/adr/0047-certificate-material-and-key-match.md) for limits,
legacy-image behavior and the independent production-audit gate.

- Security is the first requirement, not a later hardening phase.
- A feature is not complete because it works; it is complete when positive,
  negative, malformed-input, and relevant abuse cases are tested.
- Private material is never uploaded to DenyFirst and is never committed.
- Cryptographic primitives are not implemented from scratch.
- Risky operations must be explicit, auditable, recoverable, and fail closed.
- Rootwell and Porch are separate repositories and separate products.

## Plans

- Automation checks staging setup syntax without external traffic. A separate
  **Check provider connection** action requires explicit consent for one
  staging directory request; no domains/keys are sent, and no account, saved
  configuration or issuance is created. See the [ACME boundary](docs/ACME-THREAT-MODEL.md),
  [setup decision](docs/adr/0049-acme-staging-setup-check.md) and
  [directory transport](docs/adr/0050-acme-staging-directory-transport.md).
- [Product and execution plan](docs/PRODUCT-PLAN-AZ.md)
- [Historical expanded platform vision](docs/PLATFORM-VISION-AZ.md)
- [Engineering workflow](docs/ENGINEERING.md)
- [Workbench threat model](docs/THREAT-MODEL.md)
- [Security invariants](docs/SECURITY-INVARIANTS.md)
- [v0.1 format matrix](docs/FORMAT-MATRIX.md)
- [Linux access recovery and snapshot guide](docs/RECOVERY-AZ.md)

## Local Workbench interface

For a local test of the password-gated Workbench on Windows, from the Rootwell
repository in an interactive PowerShell terminal:

```powershell
$dataDir = Join-Path $env:LOCALAPPDATA "Rootwell"
$env:GOOS = "js"
$env:GOARCH = "wasm"
go build -trimpath -o web/workbench/rootwell.wasm ./cmd/rootwell-browser
Copy-Item -Force (Join-Path (go env GOROOT) "lib/wasm/wasm_exec.js") web/workbench/wasm_exec.js
Remove-Item Env:GOOS
Remove-Item Env:GOARCH
go run ./cmd/rootwelld init $dataDir
go run ./cmd/rootwelld serve $dataDir web/workbench
```

Save the one-time setup password when `init` displays it and type `SAVED` to
confirm. Open `http://localhost:4180` in the same host's browser. Signing in
with the setup password permits **only** the mandatory password-change page;
after changing it, sign in again with the replacement. Passwords are never
accepted as command-line arguments or written to daemon logs. An existing
installation's setup password cannot be redisplayed. The gateway listens on
127.0.0.1 only; it is not a remote TLS endpoint or production vault. Secure
cookies over HTTP localhost are not supported by every browser, and the
Windows ACL and native recovery boundary is not yet complete. The Windows
Workbench remains usable, but durable inventory Save is disabled there. On
Linux, recovery and complete public-inventory snapshots are offline terminal
ceremonies, not a production disaster-recovery guarantee; see the
[Linux recovery guide](docs/RECOVERY-AZ.md) and the
[loopback gate threat model](docs/LOOPBACK-GATE-THREAT-MODEL.md).
Serving `web/workbench` directly with a separate static server remains an
unauthenticated developer preview; it is not protected by `rootwelld`.

The dependency-free browser shell is available at
[`web/workbench/index.html`](web/workbench/index.html). Inspect handles one
public certificate or a collection of 1–8 public files (single DER
certificates or strict PEM bundles), up to 64 certificates and 16 MiB combined.
Convert is a separate view for exporting a selected public certificate or a
user-selected public bundle; it can reuse the current Inspect session or open
public files directly. A separate Convert picker can recognize one strict
unencrypted PKCS#8, RSA PKCS#1, or EC SEC1 private key in PEM/DER, or bounded
encrypted PKCS#8. Encrypted PKCS#8 output is the default; compatible plaintext
targets require explicit consent. A separate PFX picker creates/opens bounded
modern PFX, extracts public certificates or a newly encrypted matching key.
Creation also accepts bounded encrypted PKCS#8 input directly. A separate eye
button shows PKCS#8 PEM for at most 30 seconds: encrypted files require fresh
file-password authentication; plaintext files require renewed screen consent.
Request certificate creates a new RSA/ECDSA key and signed DNS/IP CSR locally,
or signs with an existing supported key. New keys download only encrypted as
PKCS#8 in a ZIP with the public CSR; the ZIP itself is not encrypted. Existing
CSR PEM/DER import/export checks signatures and refuses unknown attributes or
extensions. Returned-certificate comparison shows key and name differences,
not CA trust, issuance, revocation, renewal or deployment. See
[ADR 0040](docs/adr/0040-offline-key-and-csr-workbench.md).
These offline Workbench operations do not save keys to the certificate library.
PFX-key downloads remain encrypted.
These paths use the bounded Go core through WebAssembly and never post selected
bytes to a server API. A selected public certificate can
be downloaded as PEM or DER with a clearly labeled `.pem`, `.der`, `.crt`, or
`.cer` filename extension; the browser manages the final save location.
Verify checks a public server
chain against a separately selected root and hostname without network access.
An optional full SHA-256 root fingerprint pin must come from an independent
trusted source; without it, the root's identity is not independently confirmed.
Build and hosting requirements are
documented in the [browser boundary](web/workbench/README.md).

On an initialized Linux installation, `/certificates` (legacy `/inventory`
also works) is a **separate** authenticated page. The simple form selects one
certificate, optional matching private key, Check, optional service note, Save.
Check uploads selected files to your own daemon and saves nothing; Save repeats
validation and commits both objects atomically with the key separately sealed.
Rows show server-clock expiry and key-presence, not secrets. Private download
requires your current instance password and a separate key-output password;
it produces certificate PEM plus encrypted PKCS#8 PEM in an unencrypted ZIP.
Certificate-only PEM download needs no extra password. Use Workbench Convert
for other formats. PFX input, adding a key to an existing record, CA private
custody, plaintext custody export and key reveal are not part of this increment.
See [ADR 0046](docs/adr/0046-unified-certificate-library.md).

The optional public bulk form's explicit Save action sends a public certificate or
PEM bundle to that installation's loopback daemon, which parses it again and
stores it encrypted. Save is not part of the offline Workbench boundary.
Before first use, stop the daemon and run `inventory-init` with a separate
private backup location; after imports, make and verify a new full snapshot.
The [Linux recovery guide](docs/RECOVERY-AZ.md) gives the exact commands.
Expiry is now calculated against one Rootwell server-clock observation.
The page offers quiet 7/14/30/90-day reminders, a stale-result and clock
disagreement warning, and optional minute-by-minute reads while visible.
The page view stops when closed, but the daemon also performs a fixed 30-day
background expiry check while an existing ready session remains unlocked
(up to 12 hours). Logout, expiry, restart or errors pause checks; no password
is persisted for monitoring. Status and a bounded encrypted change history are
shown on the page. History is included in full snapshots; 1024 events refuse
new writes, never silently remove old history. Production retention capacity
needs a separate policy before release. Do not downgrade after history-bearing
writes. Compare replacement locally reports key/names/issuer/date differences
without candidate upload, automatic save or trust. See
[ADR 0044](docs/adr/0044-public-inventory-lifecycle-wave.md).
No email, endpoint check or renewal is performed. Search and reminder windows stay in browser memory, not stored
preferences. Server time can also be wrong; see [ADR 0041](docs/adr/0041-server-clock-inventory-reminders.md).
Owner and location notes are not
exported through the Inventory UI. On Windows, durable inventory remains
disabled. For a **fake-data, read-only visual preview only**, run
`node scripts/inventory-demo.mjs --fixture-only` and open
`http://127.0.0.1:4181/certificates`. This fixture has no authentication or
encrypted storage and is not a substitute for a Linux inventory test.
Deleting a saved record requires typing its complete fingerprint and explicit
confirmation. It changes only the current encrypted inventory; it neither
revokes a certificate nor removes a deployed copy, and older full snapshots
can restore the deleted record. Create a new full snapshot after deletion.

## Implemented commands

The separately built, explicitly network-capable `rootwell-probe` performs a
read-only TLS spot check of one literal IP and port. The regular `rootwell`
Workbench and browser stay offline. Build with
`go build ./cmd/rootwell-probe`, then run the resulting `rootwell-probe`
(`rootwell-probe.exe` on Windows):

```text
rootwell-probe --hostname portal.company.local --connect-ip 192.0.2.10 --port 443 \
  --trust-bundle company-roots.pem --root-sha256 <independently-verified-root-fingerprint> \
  --expected-leaf intended-server.crt
```

The probe checks the live TLS handshake, hostname, chain, pinned root,
Rootwell certificate policy, and exact served leaf. It does not resolve DNS,
use system roots, fetch revocation data, or check every load-balancer node.
Only probe endpoints you are authorized to contact. Obtain the expected root
fingerprint from an independent trusted source, not the same root file. The
hostname is sent as TLS SNI to the selected IP; do not disclose an internal
name to an untrusted endpoint. See
the [probe threat model](docs/LIVE-PROBE-THREAT-MODEL.md) and
[ADR 0011](docs/adr/0011-separate-explicit-live-tls-probe.md).

Inspect one local X.509 certificate in PEM or DER form:

```text
rootwell inspect certificate.pem
rootwell inspect --json certificate.der
```

The command reads at most 16 MiB, ignores the file extension, rejects multiple
or trailing objects, performs no network access, and prints escaped metadata.
A successful result means only that one certificate parsed successfully; it is
not a trust, signature, chain, hostname, or expiry-policy verdict.

Convert one public certificate between PEM and DER into a **new** file:

```text
rootwell convert --input certificate.cer --to pem --output certificate.pem
rootwell convert --input certificate.pem --to der --output certificate.der
```

The output path must not exist. PFX, private keys, and bundles are refused;
this does not check trust or produce a fullchain. `.cer` and `.crt` are filename
extensions, not separate encodings. Secret-bearing conversion has a separate
[security gate](docs/SECRET-CONVERSION-THREAT-MODEL.md).

On Linux, an offline PFX can be created from a matching certificate and
unencrypted RSA/ECDSA private key. Prepare an existing private output
directory (`mkdir -m 700 ./private-output`), then run:

```text
rootwell pfx-create --cert server.crt --key server-key.pem \
  --chain ordered-intermediates.pem --output ./private-output/server.p12
```

`--chain` is optional. If used, it contains only ordered intermediates
(nearest issuer first), not a trusted root. The command asks twice for a new,
high-entropy PFX password on a local terminal; never put it in the command
line or reuse the instance login password. The output contains the private
key and must be handled as a secret. Existing files are never overwritten.
To see the public certificates in a supported modern PFX, run:

```text
rootwell pfx-inspect --input ./private-output/server.p12
```

It prompts for the password locally, identifies the certificate matching the
contained key, and lists any additional certificates without claiming trust.
Copy the exact `SHA-256` value printed beside the desired public certificate
and save just that certificate to a new file:

```text
rootwell pfx-extract-cert --input ./private-output/server.p12 \
  --sha256 AA:BB:... --to pem --output server-public.pem
```

Replace `AA:BB:...` with the complete, uppercase fingerprint from the
inspection result. `--to der` is also available. This does not create a
fullchain, establish trust, or extract the private key. The output must not
exist; PFX and password stay local. The first reader accepts a narrow, bounded
modern profile; unsupported or older vendor PFX files fail explicitly.
Private-key extraction is a separate operation; native Windows CLI secret
output remains unsupported. On Linux, key export produces
only a new password-encrypted PKCS#8 file inside an existing owner-private
directory. Copy the complete `SHA-256` value of the **matching certificate**
from `pfx-inspect`, then run:

```text
rootwell pfx-extract-key --input ./private-output/server.p12 \
  --sha256 AA:BB:... --output ./private-output/server-key-encrypted.pem
```

Replace `AA:BB:...` with the full displayed fingerprint. The command asks
for the PFX password, then twice for a **different, high-entropy** output
password on the local terminal. Never reuse the instance login password.
This file is still sensitive even though encrypted: back it up and restrict
access. This CLI never prints a key, saves it in inventory, or exports it
unencrypted. Existing files are never replaced. The narrow modern PFX profile
remains in force. Browser operations have their own boundary described above;
native Windows CLI secret output remains unsupported. These development
features have not had their release audit;
see [ADR 0030](docs/adr/0030-pkcs12-dependency-and-profile.md),
[ADR 0031](docs/adr/0031-bounded-pfx-public-inspection.md), and
[ADR 0033](docs/adr/0033-encrypted-pfx-key-export.md).

Inspection reports public-key details, key usages, Basic Constraints, key
identifiers, SANs, critical-extension OIDs, and the SHA-256 fingerprint. JSON
uses the documented `rootwell.inspect.x509.v1` compatibility contract and
contains metadata only. See [the JSON contract](docs/INSPECT-JSON.md).

Rootwell also evaluates the certificate's encoded validity interval against the
current UTC instant. It reports `within-validity-window`, `not-yet-valid`,
`expired`, or `invalid-range`, together with explicit relative seconds and whole
days. This time-window observation is not a trust or verification verdict.

Explore public certificates in one DER file or a strict PEM bundle:

```text
rootwell explore certificates.crt
```

`explore` lists up to 64 certificates, their subject, issuer, expiry, CA flag,
and SHA-256 fingerprint. It does not select a leaf or trust anchor, verify a
chain, export files, or process PFX/private keys. The filename extension does
not determine the encoding; mixed blocks, junk, and duplicates are rejected.
Browser Explore accepts 1–8 selected public files, rejects duplicates across
them, displays the collection locally, and can download one chosen certificate
as PEM or DER from its original source file.
`.crt` and `.cer` are filename extensions, not additional encodings, and both
can be selected for either PEM or DER bytes.
It does not yet produce a combined bundle or infer chain roles. CLI `explore`
remains one-file and read-only.

Match one certificate to one unencrypted local private key:

```text
rootwell match --cert certificate.pem --key private-key.pem
rootwell match --json --cert certificate.der --key private-key.der
```

Matching accepts strict PEM or DER PKCS#8, PKCS#1 RSA, and SEC1 ECDSA keys;
PKCS#8 supports RSA, ECDSA, and Ed25519. Private-key input is capped at 64 KiB,
never printed, and cleared from Rootwell-owned input buffers on a best-effort
basis. Encrypted keys are deliberately rejected until safe passphrase input is
implemented. A mismatch prints an explicit `false` verdict and exits `1`.
Matching does not establish certificate trust or algorithm safety. See the
[match contract](docs/MATCH.md).

Verify a TLS server leaf against explicit local trust material:

```text
rootwell verify server.pem \
  --trust-bundle company-roots.pem \
  --intermediates company-intermediates.pem \
  --hostname portal.company.local
```

`--intermediates` is optional; the trust bundle and hostname are mandatory.
The leaf may be PEM or DER, while CA bundles are strict PEM certificate
bundles. Verification uses no operating-system trust store and makes no network
requests. It checks the chain, signatures, validity, TLS server usage, hostname,
constraints, and Rootwell's initial algorithm policy. It does **not** check
revocation, OCSP, CRLs, Certificate Transparency, or the certificate currently
served by a remote endpoint. See [the TLS verification contract](docs/VERIFY-TLS.md).

Private-key conversion and PFX operations have the separate, bounded boundaries
described above. Optional certificate-library custody has its own development
threat model and tests; independent release review, automatic renewal and
deployment remain separate future work.
