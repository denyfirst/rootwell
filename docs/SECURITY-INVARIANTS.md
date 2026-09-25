# Security invariants

An invariant is a behavior Rootwell must preserve, not an aspiration. Every
entry names tests that exist. A change that renames or removes a cited test must
update this file in the same commit, and CI verifies that the citations resolve.

This list guards the CLI, certificate-inspection, offline TLS verification,
and certificate/private-key match boundaries. File-writing invariants are
added with the code that first creates those risks.

## C1 — Diagnostics do not reflect command input

Unknown commands and invalid argument combinations are attacker-controlled and
may contain paths, credentials, terminal escapes, or private data. Diagnostics
state what was wrong without repeating the supplied token.

Guarded by `TestUnknownCommandDoesNotEchoInput` and `FuzzRun`.

## C2 — Exit codes and output channels are stable

Success is `0`, operational failure is `1`, and command-line usage failure is
`2`. Requested information goes to stdout; diagnostics and usage failures go to
stderr. Automation must not infer success from text.

Guarded by `TestRunContract`.

## C3 — Output failure cannot be reported as success

A closed pipe, full filesystem, or failed writer is an operation failure. Help
or version output that was not delivered must not return success.

Guarded by `TestRunReportsWriteFailure`.

## C4 — Build version output is a single safe line

Build metadata is part of the release boundary. It cannot inject additional
terminal lines or control characters into output; invalid injected metadata is
reported as `development` rather than reproduced.

Guarded by `TestVersionValue` and `FuzzVersionValue`.

## C5 — A single input read is bounded

Rootwell reads at most 16 MiB plus one detection byte. Empty and oversized
inputs fail before certificate parsing, and a file exactly at the limit remains
valid input to the boundary. Certificate-derived text and repeated metadata
also have explicit limits before terminal escaping can amplify them.

Guarded by `TestReadLimited`, `FuzzReadLimited`, and
`TestCertificateMetadataLimits`.

## C6 — Inspection accepts exactly one complete certificate

DER must be one complete ASN.1 sequence. PEM must be one header-free
`CERTIFICATE` block. Truncated, unrelated, multiple, or trailing objects fail
closed rather than being partially accepted.

Guarded by `TestInspectRejectsTrailingData`,
`TestInspectRejectsMalformedOrUnsupportedInput`, and
`FuzzInspectCertificate`.

## C7 — Requested certificate text cannot control the terminal

Subjects, issuers, SANs, and URIs are attacker-controlled even in a valid
certificate. Human output quotes them as ASCII and escapes control, Unicode,
and line-separator characters.

Guarded by `TestHumanCertificateOutputEscapesText` and
`FuzzHumanCertificateOutput`.

## C8 — Inspection errors do not disclose paths or input bytes

Open, read, parse, and format failures return fixed diagnostics. A sensitive
path or malformed file content is not reflected to either output channel.

Guarded by `TestReadDoesNotExposePath` and `TestInspectDoesNotEchoPath`.

## C9 — The local Workbench has no network or child-process capability

The executable and its production packages cannot directly import networking,
process execution, plugins, or unsafe code. Inspection never follows URLs
embedded in a certificate.

Guarded by `TestWorkbenchHasNoNetworkOrProcessImports`.

## C10 — Structured inspection output is versioned and terminal-safe

JSON output is derived from the same typed certificate result as human output.
Its schema version is explicit, repeated fields are arrays rather than `null`,
and decoded strings preserve their meaning while the emitted document contains
only printable ASCII and newlines. The schema has no raw certificate or
private-key field.

Guarded by `TestInspectJSONCommand`,
`TestJSONCertificateOutputIsASCIIAndSemantic`,
`TestJSONCertificateOutputRejectsInvalidUTF8`,
`TestJSONSchemaExcludesSecretBearingFields`, and
`FuzzJSONCertificateOutput`.

## C11 — Time-window status is bounded, explicit, and not trust

Validity endpoints are inclusive and evaluated as UTC instants. A reversed
interval is reported as `invalid-range`; relative seconds never become
negative or wrap on extreme input. Exactly one relative value is present for a
valid interval. Output calls this a time-window status so parsing or a current
date cannot be mistaken for certificate trust.

Guarded by `TestEvaluateTimeWindow`,
`TestEvaluateTimeWindowUsesInstantNotLocation`,
`TestEvaluateTimeWindowSaturatesExtremeDistance`, and
`FuzzEvaluateTimeWindow`.

## C12 — Verification trust is explicit and role-separated

TLS verification uses only caller-provided, self-signed trust anchors. System
roots are never consulted. Non-self-signed intermediates are accepted only in
the intermediate role and cannot be promoted into trust anchors.

Guarded by `TestVerifyTLSServerCertificate`,
`TestVerifyClassifiesFailures`, `TestParseBundleRejectsUnsafeContents`, and
`TestBundlesOverlap`.

## C13 — Verification enforces hostname, time, usage, and algorithm policy

A passed TLS server verdict requires a matching explicit hostname, a valid
chain at the evaluation instant, TLS server extended usage, and allowed public
key and signature algorithms. RSA keys below 2048 bits and legacy or unknown
algorithms fail closed.

Guarded by `TestVerifyClassifiesFailures`, `TestValidHostnameInput`,
`TestAllowedSignatureAlgorithms`, `TestAllowedPublicKeys`,
`TestVerifyIgnoresUnusedPolicyIncompatibleAnchor`, and
`TestSelectPolicyCompliantChain`.

## C14 — Certificate bundles are bounded and structurally strict

Trust and intermediate bundles are PEM-only, reject junk, headers, mixed block
types and duplicates, contain at most 64 certificates, and remain within the
16 MiB command input boundary.

Guarded by `TestParseBundleRejectsUnsafeContents`,
`TestParseBundleEnforcesCertificateCountLimit`, and
`FuzzParseCertificateBundle`.

## C15 — Verification output is honest and terminal-safe

Successful output identifies the TLS server profile and explicitly reports
that revocation was not checked and network access was disabled. Names and
hostnames are escaped. Failures use fixed classes and do not expose paths or
input bytes.

Guarded by `TestVerifyCommand`, `TestVerifyDoesNotEchoSensitiveInput`,
`TestHumanVerificationOutputEscapesText`, and
`FuzzHumanVerificationOutput`.

## C16 — Browser file access and asset loading are capability-separated

Workbench assets are self-hosted and contain no third-party subresources. Only
the WebAssembly loader can fetch, and it has no DOM or selected-file access.
The application script can read an explicitly selected certificate but has no
network, service-worker, dynamic-code, markup-injection, or input-persistence
capability. Same-origin CSP access exists only so the loader can obtain the
WebAssembly program.

Guarded by `TestWorkbenchPreviewIsSelfContained`,
`TestWorkbenchContentSecurityPolicyRestrictsConnections`,
`TestWorkbenchSeparatesFileAndNetworkCapabilities`,
`TestWorkbenchProcessingClaimsAreBounded`,
`TestWorkbenchInspectFileHintMatchesParserBoundary`, and
`TestWorkbenchElementReferencesResolve`. The Verify preview cannot offer
nonfunctional file inputs or silently imply that an uploaded bundle root is
trusted; this is guarded by
`TestWorkbenchVerifyPreviewDoesNotPretendToProcessFiles`. Text contrast in both themes is
guarded by `TestWorkbenchTextContrast`.

## C17 — Browser inspection is bounded, versioned, and secret-free

The browser bridge accepts one byte array no larger than 16 MiB and invokes the
same exact-certificate parser and report schema as the CLI. Oversized input is
rejected before the bridge allocates a Go copy. Failures use fixed classes and
never echo input; the result cannot include raw bytes, paths, private keys, or
stack traces. The JS and Go entry buffers are cleared after use on a best-effort
basis, but this public-certificate boundary makes no browser-wide erasure claim.

Guarded by `TestProcessCertificate`,
`TestProcessClassifiesFailuresWithoutEchoingInput`,
`TestProcessRejectsOversizedInput`,
`TestFailureResponseFailsClosedForUnknownCode`, and
`FuzzProcessReturnsJSON`. The downloadable non-production input is guarded by
`TestWorkbenchDemoCertificateIsPublicAndInspectable`.

## C18 — Private-key matching is strict, bounded, and secret-free

Matching accepts exactly one certificate and one unencrypted PKCS#8, PKCS#1,
or SEC1 private key. Private-key files are bounded to 64 KiB, large RSA work is
capped, encrypted/unsupported/malformed/mixed/trailing objects and extra DER
fields fail closed, and input paths or bytes never appear in output. Only
canonical public-key
material is compared; result models contain no private values. A mismatch is
an explicit `false` verdict with exit code 1, not a parser error or success.
The command states that trust and algorithm policy were not evaluated and that
the network is disabled.

Guarded by `TestMatchSupportedPrivateKeyEncodings`,
`TestMatchReportsMismatchAsVerdict`,
`TestMatchRejectsUnsafePrivateKeyInputs`,
`TestMatchRejectsInvalidCertificateWithoutParsingKey`,
`TestMatchRejectsOversizedRSABeforePrivateArithmetic`, `TestMatchCommand`,
`TestMatchRejectsPKCS8ExtraField`, `TestMatchRejectsPKCS8AlgorithmExtraField`,
`TestMatchRejectsPKCS1AndSEC1ExtraFields`,
`TestMatchRejectsPKCS8NestedExtraField`,
`TestMatchRejectsSEC1EmbeddedPublicMismatch`,
`TestMatchRejectsPKCS8ContradictoryECCurve`,
`TestMatchJSONCommand`, `TestMatchMismatchIsObservableFailure`,
`TestMatchJSONMismatchExitsOne`,
`TestMatchRejectsEncryptedKeyWithoutEcho`, `TestMatchReadAndOutputFailures`,
`TestMatchArgumentErrorsDoNotEchoInput`, `TestReadLimitedMapsReaderFailure`,
`TestReadLimitedClearsOversizedInput`,
`TestDestroyPrivateKeyClearsSupportedValues`, and `FuzzMatch`.

## C19 — Public bundle exploration is strict and never implies trust

`rootwell explore` accepts one complete DER certificate or a bounded PEM-only
collection. It rejects duplicates, mixed/secret blocks, junk, malformed input,
and excess size/count without printing partial certificate metadata. Results
state that verification was not performed and no trust anchor was selected;
certificate-derived text is escaped and error output does not echo input.

Guarded by `TestParsePublicCertificateAndBundle`,
`TestParsePublicBundleRejectsUnsafeContent`,
`TestParsePublicBundleEnforcesLimits`,
`TestParsePublicBundleEnforcesAggregateMetadataLimit`, `FuzzParsePublicBundle`,
`TestExploreCommand`, `TestExploreSingleDERIgnoresExtension`,
`TestExploreDoesNotPrintPartialResultOnDuplicate`,
`TestExploreRejectsMalformedAndSecretInputWithoutEcho`,
`TestExploreArgumentContract`, `TestExploreOutputEscapesCertificateText`, and
`FuzzExploreOutputIsTerminalSafe`.

## C20 — Browser bundle exploration stays public, bounded, and untrusted

Explore accepts up to eight selected files, each a public DER certificate or a
strict PEM collection through the same Go parser as CLI `explore`. The browser
enforces a 16 MiB combined and 64-certificate combined limit, rejects
fingerprint duplicates across files, and reveals no partial list if any file
fails. It rejects secret-bearing, mixed,
malformed, duplicate, excessive, and trailing input without partial results or
reflected certificate text or raw bytes. The response is versioned, bounded, and contains public
metadata only. Its explicit status is `not-performed` with trust anchor
`not-selected`; the UI uses text nodes and never turns a CA flag into trust.
Cross-file duplicate diagnostics identify the two local file positions and
display-safe bounded filenames plus the full fingerprint; within-file
duplicates identify the file only. No duplicate is silently discarded.
The file-reading script has no network or storage capability.

Guarded by `TestProcessPublicCertificateAndBundle`,
`TestProcessRejectsUnsafeInputWithoutEchoOrPartialOutput`,
`TestProcessEnforcesCertificateCountWithoutPartialResult`,
`TestFailureResponseFailsClosed`, `FuzzProcessPublicBundleReturnsJSON`,
`TestWorkbenchExploreIsPublicOnlyAndFunctional`,
`TestWorkbenchSeparatesFileAndNetworkCapabilities`, and
`TestWorkbenchDemoCertificateIsPublicAndInspectable`, and
`TestWorkbenchDemoBundleIsPublicAndExplorable`, plus the browser-state
regressions in `scripts/test-workbench-multifile.mjs` for successful
aggregation, cross-file and within-file duplicate diagnostics, unsafe filenames,
malformed second input, stale-selection
suppression, and size/count/UTF-8 metadata refusals.

## C21 — Browser export contains only the explicitly chosen public certificate

Export re-parses one bounded public source and selects a certificate by its
full fingerprint, not bundle position, subject text, or filename. It rejects
changed, secret-bearing, malformed, duplicate, excessive, and unmatched
input without partial output. PEM and DER output are re-parsed and must match
the selected DER bytes and fingerprint. Generated filenames contain only a
fixed prefix, fingerprint fragment, random suffix, and allowlisted extension.
The UI makes encoding and extension separate explicit choices: `.crt`/`.cer`
may name PEM or DER bytes; `.pem` is PEM-only and `.der` is DER-only.
The browser validates the versioned response and output again, requests a
browser-managed download, and does not write directly to the filesystem or
transmit certificate bytes to an API. Browser/OS overwrite policy is outside
this guarantee; private key and PFX are never accepted here.

Guarded by `TestPrepareExportsOnlySelectedCertificate`,
`TestPrepareRejectsChangedOrUnsafeSource`,
`FuzzPrepareNeverReturnsUnselectedCertificate`,
`TestWorkbenchPublicExportIsLocalAndExplicit`,
`TestWorkbenchDemoBundleIsPublicAndExplorable`, and
`TestWorkbenchSeparatesFileAndNetworkCapabilities`.

## C22 — Issuer candidates are signed relationships, never trust verdicts

The separate browser analysis accepts only a bounded, strict public
collection. It checks raw issuer/subject name equality, CA constraints, and
the certificate signature before listing a possible issuer. Ambiguous
parents remain separate candidates; a self-signed CA is not a trust anchor.
There is no hostname, time, complete path, algorithm-policy, revocation, or
private-key verdict. Signature work is capped at 256 checks. Malformed,
changed, duplicate, excessive, or secret-bearing input hides the entire
Explore result. The UI validates ordered full fingerprints and index bounds
before rendering relationships as text, and no network path is introduced.

Guarded by `TestProcessFindsSignedCandidatesWithoutTrust`,
`TestProcessRejectsUnsafeCollectionsWithoutEcho`,
`TestProcessBoundsSignatureWork`,
`FuzzProcessNeverReturnsTrust`,
`TestWorkbenchExploreIsPublicOnlyAndFunctional`, and the browser-state
regressions in `scripts/test-workbench-multifile.mjs`.
