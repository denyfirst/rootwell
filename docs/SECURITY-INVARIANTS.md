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

The `rootwell` Workbench executable and its production packages cannot
directly import networking, process execution, plugins, or unsafe code.
Inspection never follows URLs embedded in a certificate. The separately
invoked `rootwell-probe` is the sole, explicitly reviewed network exception;
it does not change the Workbench's offline guarantee.

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
`TestWorkbenchElementReferencesResolve`. Browser Verify requires explicit
trust and cannot silently promote a source root; this is guarded by
`TestWorkbenchVerifyRequiresExplicitTrustAndRemovesPreview`. Text contrast in both themes is
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

## C23 — Selected public bundle export cannot add or reorder certificates

The browser downloads only an explicitly checked, order-preserving subset
of the current Explore fingerprint snapshot. At export time the Go bridge
re-parses every 1–8 public source under combined 16 MiB/64-certificate
limits, rejects changed or unsafe input, and re-parses the output. Every
output DER byte string must match the corresponding selected original.
The UI validates the versioned response, ordered fingerprints, generated
filename, and output again before a browser-managed download. No private
key, automatic chain/trust verdict, network path, or direct filesystem
write is added; browser/OS save and overwrite behavior is outside scope.

Guarded by `TestPrepareExportsExplicitOrderedSubset`,
`TestPrepareRejectsChangedUnsafeAndUnselectedInput`,
`FuzzPrepareBundleNeverExportsUnselectedCertificate`,
`TestWorkbenchPublicBundleExportIsExplicit`, and the browser WebAssembly
regressions in `scripts/test-browser-wasm.mjs`.

## C24 — Browser Verify uses only explicit trust and the CLI policy

Simple and Advanced use the same `certverify.Verify` TLS server core, with a
separately selected PEM trust bundle, hostname, evaluation time, and no system
roots or network. Simple accepts bounded strict public sources and requires
one non-CA leaf; it never promotes a self-signed source root into trust or
silently selects between multiple leaves. Advanced explicitly selects one
leaf and optional intermediate bundle. The browser bridge rejects oversized
combined input before allocating extra Go copies. A versioned success must
identify explicit-file trust and the requested hostname; changed selections
or failures hide the result. Revocation, live endpoint, and private-key
possession are not claimed.

Guarded by `TestSimpleAndExplicitUseSameTrustVerdict`,
`TestSimpleNeverTrustsSourceRoot`,
`TestSimpleRejectsAmbiguousAndSecretSources`,
`TestExplicitClassifiesRefusalsWithoutPartialChain`,
`FuzzSimpleNeverUsesSourceAsTrust`,
`TestWorkbenchVerifyRequiresExplicitTrustAndRemovesPreview`, and the real
WebAssembly regressions in `scripts/test-browser-wasm.mjs`.

## C25 — Verified fullchain export re-verifies and excludes the root

A visible Verified result alone does not authorize a download. The export
path re-reads bounded public inputs and requires the complete new verified
path to match the displayed ordered fingerprint snapshot under the same
hostname, explicit trust, mode, and evaluation time. Any refusal or changed
path returns no bytes and invalidates the browser's earlier verdict. The
output is canonical PEM in leaf/intermediate path order; the trust root,
private key, unrelated certificates, and unverified candidates are absent.
Go and browser code re-parse and compare the output before requesting a
browser-managed download. The file is a verdict at the displayed evaluation
time, not proof of current validity or live deployment.

Guarded by `TestPrepareVerifiedFullchainExcludesRootAndPreservesVerifiedOrder`,
`TestPrepareRefusesUnverifiedChangedAndUnsafeInputs`,
`TestPrepareExplicitNeedsSameVerifiedPath`,
`FuzzPrepareNeverExportsUnverifiedSource`,
`TestWorkbenchVerifyDemoIsPublicAndExportsOnlyVerifiedPath`, and the real
WebAssembly and browser-state regressions in `scripts/test-browser-wasm.mjs`
and `scripts/test-workbench-multifile.mjs`.

## C26 — Optional root pin binds the offline verdict to a full fingerprint

Browser Verify accepts an optional 32-byte SHA-256 certificate fingerprint,
written as 64 hex digits or 32 colon-separated hex bytes. The Go verification
core compares it against the final trust anchor in the verified path, not the
first item in a bundle or a self-signed root in source files. A malformed or
mismatched pin returns no chain or Verified result. Both Simple and Advanced
use this rule. Editing the field invalidates the current verdict and export;
the existing export re-verifies the complete ordered fingerprint path, including
that root. An absent pin is reported as `not-provided`, never as authenticated
root identity. A matching pin proves agreement with the supplied fingerprint
only: independent authentication of its source is the operator's task.

Guarded by `TestRootPinMatchesOnlyCompleteVerifiedPathAnchor`,
`scripts/test-browser-wasm.mjs`, `scripts/test-workbench-multifile.mjs`, and
`TestWorkbenchVerifyRequiresExplicitTrustAndRemovesPreview`.

## C27 — A live TLS observation has a separate, explicit network boundary

Only `cmd/rootwell-probe/main.go` may import Go networking in production.
Invoking the offline `rootwell` or browser cannot trigger the probe. The probe
requires literal IP, port, DNS hostname/SNI, a strict explicit trust bundle,
an independently obtained full root SHA-256 pin present in that bundle, and
an expected public leaf before connecting. It makes one bounded TCP/TLS
connection, does no DNS, HTTP, AIA, CRL, OCSP, child process, application
request, or file write, and never uses system roots. Go TLS must complete
ordinary verification against only the pinned root; a connection callback
checks exact served leaf identity and Rootwell policy using only intermediates
the peer actually sent. A failed check emits no success result. A pass is one
vantage's observation at one time, not universal MITM absence or revocation
evidence. See ADR 0011 and the separate probe threat model.

Guarded by `TestWorkbenchHasNoNetworkOrProcessImports`,
`TestLiveProbeMatchesPinnedRootAndServedLeaf`,
`TestLiveProbeRequiresPeerToServeIntermediate`,
`TestLiveProbeRefusesMismatchAndPreNetworkFailures`, and
`TestLiveProbeRejectsMalformedArgumentsBeforeNetwork`.

## C28 — Local expiry overview cannot become a trust or renewal verdict

Explore returns both X.509 validity endpoints as canonical UTC timestamps.
The browser rejects malformed dates before showing any result and classifies
all selected public certificates against one browser-clock snapshot. It
distinguishes expired, not-yet-valid, invalid ranges, 0–30 days, 31–90 days,
and later expiry without treating CA certificates as trusted. The 30/90-day
thresholds are fixed 24-hour intervals; the X.509 end instant is inclusive.
Results are in-memory only, cleared on selection or failure, and never imply
alerts, renewal, revocation, server deployment, or clock authenticity.

Guarded by `TestProcessPublicCertificateAndBundle`,
`TestWorkbenchExploreIsPublicOnlyAndFunctional`, and
`scripts/test-workbench-multifile.mjs`.

## C29 — Guided handoff cannot choose trust or conceal changed sources

Explore's plain-language guide is based only on validated public metadata
and signature-backed possible issuer links. It never says a candidate is
trusted or verified. Only an explicit click transfers selected File references,
and only when exactly one certificate lacks the CA flag. The user must still
provide a hostname and a separate trust file. Before invoking the unchanged
Go Simple verifier, the browser re-parses every guided source and compares
its ordered full SHA-256 certificate fingerprints with the Explore snapshot.
Changed or malformed files, new selection, and manual source replacement
invalidate the handoff. No source root becomes a trust anchor. Verification
failure guidance is fixed by allowlisted error code, not raw input text.

Guarded by `TestWorkbenchExploreIsPublicOnlyAndFunctional`,
`TestWorkbenchVerifyRequiresExplicitTrustAndRemovesPreview`, and
`scripts/test-workbench-multifile.mjs`.

## C30 — Possible signing links never become a trust path

The Explore link guide renders validated signature-backed possible-parent
indices as text only. It neither chooses a signer when multiple candidates
exist nor infers a trusted root from a self-signed certificate. Missing
parents remain visible. Changing source order only changes card numbers;
new selection or failed analysis clears old rows. The explicit Verify trust
file remains untouched.

Guarded by `TestWorkbenchExploreIsPublicOnlyAndFunctional` and
`scripts/test-workbench-multifile.mjs`.

## C31 — Public report is explicit, bounded, and snapshot-bound

A report is requested only by the user after a successful public Explore.
Every source is re-read and its ordered full certificate fingerprints must
match the displayed snapshot. Selection changes, parse failure, oversized
inputs or report output, and stale work prevent the browser download. The JSON
contains public metadata and explicit non-verification markers, not source
filenames, private keys or a trusted-root verdict. The browser controls final
file saving; internal certificate names may still be sensitive to the owner.

Guarded by `TestWorkbenchExploreIsPublicOnlyAndFunctional` and
`scripts/test-workbench-multifile.mjs`.

## C32 — Initial installation password cannot open stored data

The generated password is per-installation and exists only for first-use
rotation. The access envelope authenticates its state. Before rotation,
`Open` never returns the data key; after rotation, the initial password no
longer works. Failed and weak changes leave the original setup state intact.
An existing access file is not overwritten and malformed or unsafe files fail
closed. This package is not yet an HTTP login or production vault.

Guarded by `TestInitialPasswordRequiresChangeBeforeDataKeyIsAvailable`,
`TestFailedChangesKeepInitialPasswordAndRejectWeakReplacement`,
`TestInitialPasswordIsUniqueAndNotStoredInPlaintext`, and
`TestMalformedAndUnsafeAccessFilesFailClosed`.

## C33 — Loopback gate separates setup from normal access

Only a local interactive init can show a new per-installation setup password.
An initial-password session can see the password-change page, never the
Workbench or its assets. A successful change invalidates every prior session;
normal access requires fresh sign-in with the replacement password. The server
binds loopback only and rejects unexpected Host, cross-origin mutation,
malformed requests, oversized bodies and excess password attempts. No vault or
remote transport is implied.

Guarded by `TestInitialLoginIsSetupOnlyUntilPasswordChange`,
`TestGateRejectsCrossOriginHostAndMalformedAuthentication`,
`TestGateRateLimitsAndExpiresSessions`,
`TestInitRequiresSaveConfirmationAndNeverReprintsPassword`,
`TestReadyPasswordChangeRevokesAllSessionsAndLogoutOnlyOwn`,
`TestAuthFormsCannotFallBackToPasswordInGetURL`,
`TestGatewayRefusesIncompleteBrowserAssets`,
`TestPasswordChangeValidationIsSpecificWithoutEchoingSecrets`, and
`scripts/test-rootwelld-auth.mjs`.

## C34 — Sessions cannot silently survive an observed access-file change

A session is tied to the exact encrypted access-file bytes seen during login.
The gateway refuses login if that file changes across password verification.
For subsequent requests, an unreadable, reader-rejected, or different access file
invalidates the old session, including external password rotation. A new
password can create a new session. This does not provide interprocess locking,
request-atomic authorization, or protection against same-byte rollback.

Guarded by `TestSessionIsRevokedWhenAccessFileChangesOutsideGate` and
`TestInitialLoginIsSetupOnlyUntilPasswordChange`.

## C35 — Draft inventory cannot accept secret-bearing or partial imports

The in-memory catalog imports only bounded, strictly parsed public X.509
objects. Mixed, malformed, secret-bearing, oversized, and duplicate inputs
leave the catalog unchanged. Concurrent duplicate attempts add at most one
record. Returned byte slices cannot mutate stored records. No trust verdict,
disk persistence, or HTTP import is introduced by this draft.

Guarded by `TestImportPublicCertificateAndDetachResults`,
`TestDuplicateAndMalformedImportsAreAtomic`, `TestLabelsAndCapacityFailClosed`,
`TestConcurrentDuplicateImportHasOneWinner`, and
`TestBundledPublicCertificatesRemainUnverified` and
`TestOversizedSingleCertificateIsRejectedWithoutMutation`.

## C36 — In-memory inventory encryption binds its expected context

The standalone codec uses AES-256-GCM with a random nonce and rejects an
invalid key, missing installation/record/generation context, oversized input,
tampering, wrong key, and cross-installation/cross-record/cross-generation
substitution without returning partial plaintext. It does not persist data or
stop rollback to an older ciphertext with the same expected generation.

Guarded by `TestSealRoundTripUsesFreshNonceAndHidesPlaintext`,
`TestSealRejectsWrongKeyContextSwapAndTampering`,
`TestSealBoundsAndMissingContextFailClosed`, `TestSealWorksWithRandomDataKey`,
and `FuzzOpenSealedRecord`.

## C37 — New installation identity is authenticated and stable

Each new access envelope has a random 128-bit ID authenticated by the wrapped
data-key AEAD. Setup cannot release the key; password changes preserve key
and ID; malformed or altered identity is refused. Legacy v1 files remain
readable and rotatable but cannot claim an ID or silently migrate. No durable
inventory, recovery credential, or backup is enabled by this invariant.

Guarded by `TestV2IdentityIsUniqueAuthenticatedAndSurvivesPasswordChanges`,
`TestLegacyV1CanStillOpenButCannotClaimAnIdentity`, and
`TestV2RejectsMalformedIdentityAndVersion`.

## C38 — Offline recovery codec does not silently enroll credentials

The standalone codec generates a fresh 256-bit random code and wraps only an
existing 256-bit data key for an explicit 128-bit installation ID. Wrong code,
altered wrap, changed ID, malformed input, and cross-installation substitution
return no key. It creates no file or endpoint, and is not a backup or working
lost-password recovery ceremony.

Guarded by `TestRecoveryWrapRoundTripIsRandomAndBoundToInstallation`,
`TestRecoveryWrapRejectsTamperingAndMalformedInputs`, and
`FuzzOpenRecoveryWrap`.

## C39 — Legacy identity preparation does not mutate access

Only a password-authenticated, ready v1 access snapshot can prepare an
encrypted v2 candidate. It preserves the exact data key and password, creates
a fresh random ID, and binds the candidate to the source revision. Wrong
password, setup state, already-v2 state, malformed/oversized input, and symlink
are refused without a candidate. The source file is never changed. A revision
alone is not a lock or authorization to install the candidate.

Guarded by `TestPrepareIdentityUpgradePreservesKeyWithoutChangingSource` and
`TestPrepareIdentityUpgradeRefusesWrongStateAndUnsafeInput`.

## C40 — Linux access changes serialize cooperating writers

Linux access-password changes require an exclusive advisory lock on a stable,
private lock file inside an owner-private directory. Busy, permissive, and
symlink lock paths are refused without changing access. Once replacement
succeeds, the directory is synced; a failure leaves an explicitly uncertain
outcome. The lock protocol does not bind external writers or network volumes.

Guarded by `TestLinuxAccessWriterLockRejectsConcurrentPasswordChange` and
`TestLinuxAccessWriterRefusesUnsafeDirectoryAndLock`, and
`TestPostReplaceSyncFailureReportsUncertainOutcome`, and
`TestUncertainPasswordChangeRevokesSessionsWithoutFalseSuccess`.

## C41 — Linux identity installation validates before replacing

Under the private Linux writer lock, installation requires the exact source
revision, authenticated ready v1 source, authenticated ready v2 candidate,
same password and data key, and matching candidate ID. Stale, replayed,
tampered, wrong-key, busy, and unsupported-platform attempts fail closed.
Pre-rename errors preserve the original; post-rename sync/readback errors
report uncertainty. No CLI/browser migration or backup is enabled.

Guarded by `TestLinuxIdentityUpgradeCommitsOnlyMatchingReadyV1`,
`TestLinuxIdentityUpgradeRejectsStaleCandidate`,
`TestLinuxIdentityUpgradeRejectsTamperingWrongKeyAndBusyLock`,
`TestLinuxIdentityUpgradeFaultsPreserveOrReportUncertain`, and
`TestIdentityUpgradeCoreRejectsWrongKeyAndStaleRevision`,
`TestIdentityUpgradeCorePreservesPrewriteFailureAndReportsPostwriteUncertainty`,
`TestIdentityUpgradeCoreUsesOneCandidateSnapshot`,
and `TestNonLinuxIdentityUpgradeFailsClosed`.

## C42 — Linux offline recovery keeps the same data key and rotates authority

Only a password-authenticated ready v2 installation may enroll recovery;
ready v3 requires the password to rotate it. The recovery wrap and a keyed
confirmation are embedded in one v3 access envelope and password-authenticated.
A valid code can reset the password while preserving the data key and ID, but
the current envelope receives a fresh code so replay of the old code fails.
Wrong credentials, tampering, unsafe directory, busy lock, and unsupported OS
do not write. Pre-replacement faults preserve the source; post-replacement
sync/readback faults are uncertain and return no code. This is internal core,
not a backup or operator-facing recovery promise; old offline backups remain
usable with their old codes.

Guarded by `TestRecoveryEnrollmentRotationAndPasswordResetPreserveIdentity`,
`TestRecoveryWrapSurvivesPasswordRotation`,
`TestRecoveryRefusesWrongCredentialAndTamperedEnvelopeWithoutWriting`,
`TestRecoveryWriteFaultsDoNotReturnCode`,
`TestLinuxRecoveryCeremonySerializesAndPreservesDataKey`,
`TestLinuxRecoveryRefusesUnsafeStore`, and
`TestNonLinuxRecoveryCeremonyFailsClosed`, plus
`FuzzRecoveryEnvelopeParsing`.

## C43 — Access snapshots prove both recovery paths and never overwrite

Linux access-only export requires an authenticated ready v3 source, current
password, and matching offline recovery code under the access writer lock.
The snapshot has a fresh ID and data-key MAC over its exact bounded encrypted
access bytes. It is written as a new private file in a separate private
directory, synced, and read back. Verification refuses wrong credentials,
tampering, truncation, trailing data, and oversized input without releasing a
key. Restore verifies before writing and accepts only an otherwise empty
private directory; it never overwrites an installation. Post-write faults are
uncertain. This does not back up inventory records or prevent old-snapshot
replay.

Guarded by `TestAccessSnapshotVerifiesWithPasswordOrRecoveryCode`,
`TestAccessSnapshotRejectsWrongCredentialsTamperingAndTruncation`,
`TestAccessSnapshotRequiresEnrolledRecovery`,
`TestLinuxAccessSnapshotFreshRestoreDrill`,
`TestLinuxAccessSnapshotRefusesUnsafePathsAndTampering`,
`TestLinuxAccessSnapshotPostWriteSyncFailureIsUncertain`,
`TestNonLinuxAccessSnapshotFilesystemOperationsFailClosed`, and
`FuzzOpenAccessSnapshot`.

## C44 — Offline Linux ceremonies never take secrets from argv or a live daemon

The operator commands require interactive stdin/stdout terminals and read
passwords and recovery codes without local echo. Their argv contains only
paths and the non-secret unlock method. A private operation lock excludes a
running Linux daemon and another offline ceremony. Recovery output is printed
only to the trusted terminal after persistence; display failure does not
return the code in an error. Linux-only filesystem operations refuse on other
platforms. This is not protection against compromised terminals, shell
history containing user-supplied secret arguments, an older non-cooperating
daemon, or a malicious same-user process.

Guarded by `TestOfflineCommandClassificationAndNoSecretArgv`,
`TestRecoveryCodeDisplayFailureDoesNotReturnTheCode`,
`TestLinuxOfflineCeremonyEnrolsSnapshotsRestoresAndResets`,
`TestLinuxOfflineCeremonyRefusesRunningDaemonAndBadArguments`,
`TestLinuxOperationLockExcludesAnotherDaemonOrCeremony`,
`TestLinuxOperationLockRefusesUnsafeDirectoryAndLock`, and
`TestNonLinuxOfflineCeremonyFailsClosed`.

## C45 — Complete inventory images authenticate context before releasing records

The standalone image codec MACs a canonical bounded manifest with the
installation data key and verifies every encrypted record against the exact
installation, certificate digest, and image-local generation before returning
any records. It rejects duplicate, malformed, secret-bearing, corrupt, and
cross-installation input without partial results. The generation is counted
per import or explicit location change, far below the random-nonce AEAD per-key
usage limit. This codec
does not write files, enable HTTP import, establish an external trusted
generation anchor, or prevent replay of an older complete authenticated image.

Guarded by `TestCreateAppendOpenAndRejectDuplicate`,
`TestCorruptionContextAndMalformedImportFailClosed`,
`TestManifestRejectsAuthorizedButInconsistentRecord`, and `FuzzOpenImage`.

## C46 — Linux inventory activation and full snapshots preserve recoverability

Only a recovery-enrolled ready installation can initialize durable Linux
public inventory. A verified full snapshot of the planned empty image is
created in a separate private directory before the inventory file is made
visible. Subsequent imports validate the entire authenticated image and
atomically replace it under the installation writer lock; post-rename faults
are uncertain. Offline full export captures the exact access envelope and
inventory image under both the daemon operation lock and writer lock. Restore
authenticates the pair before writing only into a fresh private directory,
inventory first and access last. Neither an access-only backup nor an older
complete snapshot guarantees current inventory state. Windows operations
fail closed; filesystem-level full-image rollback remains undetectable.

Guarded by `TestFullSnapshotPasswordAndCodeRoundTrip`,
`TestFullSnapshotRefusesWrongCredentialsAndIncompletePairs`,
`TestLinuxInventoryDurableImportAndFreshFullRestore`,
`TestLinuxInventoryRefusesUnsafeAndBusyOperations`,
`TestLinuxInventoryPostRenameSyncFaultIsUncertain`,
`TestLinuxInventoryPreRenameDiskFaultPreservesOriginal`,
`TestLinuxFullSnapshotRefusesUnsafePathsAndTampering`,
`TestLinuxInventoryCeremoniesRequireRecoveryAndRestoreFresh`,
`TestNonLinuxDurableInventoryFailsClosed`, and `FuzzOpenFullSnapshot`.

## C47 — Public inventory upload is explicit, authenticated, and non-verifying

The offline Workbench retains its no-upload boundary. A separate self-hosted
Inventory page discloses that Save sends public certificate bytes to the
loopback daemon. The API requires a ready revision-bound session; POST also
requires exact same-origin and a custom header, rejects duplicate JSON fields
and oversized bodies, and reuses the strict public parser before any atomic
write. GET requires the custom header and refuses cross-site fetch metadata.
Legacy/setup sessions and unsupported platforms cannot write. Responses omit
DER/private bytes, label every list as unverified, and show import generation,
server-clock save time, and browser-clock expiry without audit claims. No automatic backup, trust, deployment,
revocation, notification, or private-key support is implied. A ready Linux
session holds the data key in process memory until revoked/expired; map erasure
is best effort and a compromised process is outside this boundary.

Guarded by `TestLinuxInventoryAPIRequiresReadySessionAndExplicitSave`,
`TestInventoryInputRejectsDuplicateUnknownAndOversizedJSON`,
`TestInventoryOutputNeverSerializesCertificateBytes`,
`TestCreateAppendOpenAndRejectDuplicate`,
`TestOlderImageWithoutImportTimeStillOpens`,
`TestWorkbenchPreviewIsSelfContained`, and
`scripts/test-rootwelld-inventory.mjs`.

## C48 — Linux container volumes keep recovery separate and reject unsafe reuse

The development Compose service binds the existing daemon to Linux host
loopback and mounts only its private data directory. Offline maintenance has
no network and mounts the backup directory only for an interactive ceremony;
neither password nor recovery code is configured through argv or environment.
A disposable CI drill crosses actual container process restarts and separate
bind mounts, verifies a complete fresh-volume restore, refuses wrong code,
tampered snapshot, permissive data directory, duplicate import, overwrite,
and live-daemon backup. It does not establish offsite durability, automatic
backup, external anti-rollback, Windows support, or production readiness.

Guarded by `TestContainerVolumeDrill`,
`scripts/test-container-config.mjs` (overprivileged and ephemeral-volume
sabotage), and `scripts/test-container-volume.sh` in the required Linux
container CI job.

## C49 — One public certificate can have bounded manual locations, never a deployment verdict

The fingerprint remains unique; duplicate imports still fail. An explicit
same-origin, session-bound POST can attach one of at most 32 plain-text,
nonempty, exact location labels to an existing certificate. It requires the
generation last displayed, authenticates the whole image, and atomically
reseals only that certificate under a fresh generation. Original import
generation/time and DER remain unchanged. Old images without additional
locations remain readable. Stale generation, missing certificate, duplicate,
malformed or excessive labels, corrupt image, and cross-origin or anonymous
requests do not write. API and UI say locations are operator notes, not
verified deployments. Each successful note needs a new full snapshot;
existing snapshots do not acquire it automatically.

Guarded by `TestAssociateLocationIsBoundedExplicitAndDetached`,
`TestAssociateLocationPreservesOneCertificateAndImportProvenance`,
`TestAssociatedImageRejectsAuthorizedMalformedLocationPayload`,
`TestOlderImageWithoutImportTimeStillOpens`,
`TestLinuxInventoryAssociationsSurviveRestartAndFullRestore`,
`TestLinuxInventoryLocationAPIIsExplicitAndGenerationBound`,
`TestLocationInputRejectsMalformedAndDuplicateFields`,
`TestInventoryOutputNeverSerializesCertificateBytes`,
`TestContainerVolumeDrill`, and `scripts/test-rootwelld-inventory.mjs`.

## C50 — Owner correction is explicit, generation-bound, and non-verifying

An authenticated same-origin POST can replace one public certificate's manual
owner note or explicitly clear it to unknown. The complete encrypted image
and displayed generation are checked before mutation. Malformed or non-string
owner, no-op, missing fingerprint, stale tab, unauthorized session, and
cross-origin requests cannot write. A successful correction changes only the
encrypted owner note and image generation; DER, locations, original import
generation/time remain unchanged. API output omits DER and makes no verified
ownership claim. A new full snapshot is manual; older backups may retain the
previous note. There is no tamper-evident edit history or deletion claim.

Guarded by `TestUpdateOwnerChangesOnlyDetachedManualNote`,
`TestUpdateOwnerPreservesCertificateLocationsAndProvenance`,
`TestLinuxInventoryOwnerCorrectionIsDurableAndRestorable`,
`TestLinuxInventoryLocationAPIIsExplicitAndGenerationBound`,
`TestOwnerInputRequiresExplicitBoundedStringAndGeneration`, and
`scripts/test-rootwelld-inventory.mjs`.

## C51 — Manual location correction cannot become deployment or certificate deletion

An authenticated same-origin POST can rename one exact location label to a
valid, unused label or remove one exact label. It requires the displayed
generation and authenticates the whole image before lookup; stale, malformed,
unknown, duplicate, no-op, cross-origin, and unauthorized requests cannot
write. Only the selected record is resealed. DER, fingerprint, owner, original
import provenance, and other records remain unchanged. Removing the first
label promotes the next; removing the last leaves an unknown location and
does not delete the certificate or touch a server. UI removal requires an
explicit confirmation checkbox. Older snapshots can restore old notes.

Guarded by `TestRenameAndRemoveLocationPreserveCertificateAndUnknownState`,
`TestChangeLocationPreservesCertificateAndImportProvenance`,
`TestLinuxLocationCorrectionsSurviveFullRestoreAndRejectStaleWrites`,
`TestLinuxInventoryLocationAPIIsExplicitAndGenerationBound`,
`TestLocationChangeInputRequiresExactActionAndFields`, `TestContainerVolumeDrill`,
and `scripts/test-rootwelld-inventory.mjs`.

## C52 — Expiry triage is a local view, not a trust verdict

The saved public inventory response is fully validated before local-only
priority sorting, text search, and expiry or missing-note filters. At the exact
NotAfter instant the certificate is expired. Counts include all records even
when filtered; the shown count states the distinction. Filtering neither
transmits metadata nor rereads selected files, stores search terms, changes
the encrypted image, or opens a correction panel for a stale selection. The
original browser-clock view is superseded by one server-clock observation
(ADR 0041, C64). Search and filters remain browser-memory-only. Next-action
text does not claim verified deployment, trust or renewal. Incorrect clocks
remain a residual risk; reminders are page-only, not guaranteed delivery.

Guarded by `scripts/test-rootwelld-inventory.mjs`.

## C53 — Inventory UI does not export sensitive metadata

The earlier selected-record JSON download is retired from the Inventory UI.
The page has no bulk-selection or download path; searching and opening
details do not transmit inventory notes. Certificate download stays in the
public-only Workbench flows, and encrypted full backup stays offline. The
development visual demo uses generated fake records, binds loopback only,
disables writes, and never demonstrates durable storage or authentication.

Guarded by `scripts/test-rootwelld-inventory.mjs` and
`scripts/test-inventory-demo.mjs`.

## C54 — Record deletion is exact, explicit, and never a revocation claim

One saved public certificate and its manual notes can be removed from the
current encrypted image only by an authenticated ready same-origin POST with
the displayed generation, a duplicated exact fingerprint, and a fixed
confirmation phrase. The UI additionally requires the operator to type the
full displayed fingerprint and check a backup warning. The whole image is
authenticated before deletion and atomically replaced; all surviving records
retain their bytes, notes, and import provenance. Stale, absent, malformed,
anonymous, cross-origin, and headerless attempts do not write. Removing the
last record leaves a valid empty image. An older full snapshot still restores
the old certificate, while a new snapshot restores its absence. This does
not securely erase old bytes, delete backups, revoke a certificate, or alter
a server deployment. No automatic deletion occurs.

Guarded by `TestDeleteRecordIsExactGenerationBoundAndRecoverableFromOldImage`,
`TestLinuxInventoryExplicitDeletionAndOldSnapshotRetention`,
`TestInventoryDeleteInputRequiresTypedFingerprintConfirmationAndGeneration`,
`TestLinuxInventoryLocationAPIIsExplicitAndGenerationBound`, and
`scripts/test-rootwelld-inventory.mjs`.

## C55 — Public CLI conversion cannot become key export or overwrite

The CLI accepts one strict public X.509 certificate and emits equivalent PEM
or DER bytes only to a new file. PFX, private keys, mixed/trailing input,
unsupported encodings, duplicate flags, and existing or symlink destinations
fail without publishing an output or disclosing input in diagnostics. The
input is unchanged. Staged public bytes are read back before publication.
The operation is offline and is not a reviewed secret-output primitive or a
trust verdict. Crash durability and staging cleanup after abrupt termination
are not guaranteed.

Guarded by `TestConvertPublicCertificateBothDirections`,
`TestConvertRefusesExistingOutputAndSymlink`, and
`TestConvertRejectsMalformedSecretAndUsage`.

## C56 — Offline PFX creation never becomes implicit key custody

Only a local interactive Linux CLI invocation may create a password-protected
PFX from one strict non-CA certificate, matching unencrypted RSA/ECDSA key,
and optional ordered signing issuers. PFX output uses a pinned modern profile,
is decoded and compared, and is published only to a new file inside an
owner-private directory with no overwrite. Wrong key, malformed/duplicate/
unrelated chain, weak algorithm policy, non-TTY, password mismatch, unsafe
directory, symlink destination, and unsupported OS fail closed. No password,
private key, or PFX bytes are written to stdout, stderr, logs, argv, or JSON.
The command does not store a key in the inventory, establish trust, or support
PFX import. Post-publication filesystem failure is uncertain, not success;
runtime memory erasure and weak human password detection are not guaranteed.

Guarded by `TestCreatePFXMatchesKeyAndOrderedIssuer`,
`TestCreateRejectsMismatchAndUnsafeMaterial`,
`TestCreateRefusesWeakRSACertificate`,
`TestCreatedPFXOpensInIndependentOpenSSL`,
`TestPFXCreateRequiresSecretReaderBeforeKeyRead`,
`TestPFXCreateInteractiveAndNoOverwrite`,
`TestPFXCreateRefusesPasswordMismatchAndBadUsage`,
`TestPFXCreateUnsupportedOSRefusesBeforeKeyRead`,
`TestWriteNewPrivateAndNoOverwrite`,
`TestWriteNewRejectsUnsafeDirectoryAndSymlink`, and
`TestNonLinuxSecretOutputFailsClosed`.

## C57 — PFX inspection is bounded, authenticated, public-only, and non-trusting

The offline CLI accepts at most 1 MiB of a narrow modern PFX profile, checks
the three visible envelope KDF work factors before password-based decoding,
uses a 10-second one-shot CLI deadline, and requires a
local interactive password. It enumerates supported bags rather than silently
assuming the first certificate is the leaf, requires exactly one key and one
matching non-CA certificate, rejects duplicate or ambiguous material, and
returns only public metadata. Additional certificates remain untrusted and
unordered. Wrong password, tampering, malformed/trailing input, unsupported
profile, excessive KDF cost, and non-TTY input produce no partial public
result or secret echo. It never exports or persists a key, and does not prove
hostname, trust, revocation, or a live deployment. Runtime memory erasure is
best effort, not guaranteed. An unbounded KDF hidden in an encrypted safe is
not detected before decode; the CLI deadline limits the operator-facing wait,
but this decoder must not be reused in a long-lived process.

Guarded by `TestInspectModernPFXPublicOnly`,
`TestInspectRejectsWrongPasswordTamperAndUnsupported`,
`TestPreflightRejectsExcessiveKDFBeforeDecode`,
`TestInspectRejectsMismatchedKeyAndDuplicateCertificate`,
`TestInspectShowsAdditionalCertificateWithoutTrustClaim`,
`TestInspectRejectsLegacyProfileWithoutFallback`,
`TestInspectModernOpenSSLGeneratedPFX`,
`FuzzPFXPreflight`, `TestPFXInspectShowsOnlyPublicSummary`, and
`TestPFXInspectRefusesNonTTYAndWrongPasswordWithoutPartialOutput`, and
`TestPFXInspectRejectsUnsupportedBeforePasswordPrompt`, and
`TestPFXInspectDeadlineReturnsWithoutPartialResult`, and
`TestPFXInspectDecoderPanicIsNotPrinted`.

## C58 — PFX public extraction is exact-selection and never key export

The offline CLI accepts only a complete canonical SHA-256 fingerprint printed
by inspection, authenticates and validates the same bounded modern PFX profile,
and writes exactly the selected public certificate as PEM or DER to a new file.
It does not choose by order, infer a chain or trust, overwrite an existing
path, publish a key/PFX/password, or follow a substituted input path after the
original bounded read. Wrong selection or password, malformed/oversized PFX,
non-TTY input, unsupported output format, and output collision produce no
partial file. The public file writer is not a secret-output primitive, and
the one-shot decoder boundary from C57 still applies.

Guarded by `TestCertificateDERSelectsExactPublicObject`,
`TestInspectShowsAdditionalCertificateWithoutTrustClaim`,
`TestInspectModernOpenSSLGeneratedPFX`,
`TestPFXExtractCertWritesOnlySelectedPublicCertificate`,
`TestPFXExtractCertBindsSelectionToAlreadyReadBytes`,
`TestPFXExtractCertRefusesWrongSelectionPasswordAndOutputCollision`, and
`TestPFXExtractCertRequiresTTYAndValidProfileBeforePrompt`.

## C59 — PFX private-key export is encrypted, isolated, and no-overwrite

The offline Linux CLI may export only the one key bound to an exact inspected
non-CA certificate fingerprint from an authenticated, bounded modern PFX.
The output is one password-encrypted PKCS#8 PEM block, never plaintext,
stdout, JSON, inventory, or browser content. A new terminal-entered output
password is confirmed, meets policy, and differs from the PFX password.
Unsupported OS, non-TTY, malformed/oversized/legacy/tampered input, wrong
password or fingerprint, unsafe directory, existing/symlink destination, and
failed output verification do not publish a key. The PFX input is read once
before prompting; the decoder and encryption run within the one-shot CLI
deadline. Output is written through the private no-overwrite file primitive.
This does not establish CA trust and does not guarantee runtime zeroization or
cancel an already timed-out decoder inside a reusable process.

Guarded by `TestExportProducesOnlyEncryptedMatchingPKCS8`,
`TestExportRSAKeepsMatchingKeyEncrypted`,
`TestExportRefusesWrongSelectionPasswordAndTamper`,
`TestPFXExtractKeyEncryptedPrivateNewFileAndOpenSSL`,
`TestPFXExtractKeyRefusesWrongPasswordSelectionAndCollision`,
`TestPFXExtractKeyBindsReadBeforePromptAndRejectsPasswordReuse`,
`TestPFXExtractKeyUnsupportedPlatformRefusesBeforeInput`, and
`TestPFXExtractKeyRejectsNonTTYAndUnsafeArguments`.

## C60 — Browser private conversion is separate and bounded

Only the explicit private-key Convert picker accepts one strict unencrypted
PKCS#8, RSA PKCS#1, or EC SEC1 PEM/DER key or a bounded modern encrypted
PKCS#8 PEM/DER key up to 64 KiB. Inspection returns public metadata only.
Encrypted input requires its current password on inspection and again on
export. Export re-reads the file and binds it to the full displayed public
fingerprint. Encrypted PKCS#8 output with a fresh 20–128 printable-character
password is default; plaintext compatible targets require separate visible
selection and confirmation. Malformed, changed, oversized, wrong-fingerprint,
wrong-password, unsupported target/profile, and PFX input publish no key.
The browser script cannot upload or persist selected bytes;
buffers and password fields are cleared best-effort. The public Inspect,
Verify, and certificate Convert inputs remain public-only. The browser and OS
may retain memory/download copies and control file permissions; no vault or
per-user key authorization is claimed.

Guarded by `TestInspectAndExportEncryptedPrivateKeyFormats`,
`TestPrivateConversionRefusesMalformedChangedAndWeakPassword`,
`FuzzInspectPrivateKeyNoSecretEcho`,
`TestEncryptedInputAndPlaintextTargets`,
`TestEncryptedInputRefusesUnsafeProfilesAndNoPartialExport`,
`TestWorkbenchPrivateConversionSeparatesInputAndOutputPasswords`,
`TestWorkbenchSeparatesFileAndNetworkCapabilities`, and
`TestInitialLoginIsSetupOnlyUntilPasswordChange`, plus
`scripts/test-browser-wasm.mjs` and `scripts/test-workbench-private.mjs`.

## C61 — Browser PFX stays isolated, bounded, and honest

Only the separate PFX picker accepts a password-protected PFX, at most 1 MiB,
with the authenticated modern profile and pre-decryption KDF caps. Inspection
returns public certificate metadata only and labels additional certificates
as included, not trusted. Each extraction re-reads and reauthenticates the
selected file; public extraction binds its displayed full fingerprint, while
private extraction binds the matching certificate and outputs only newly
encrypted PKCS#8 PEM under a distinct new password. Creation accepts one
strict matching RSA/ECDSA key (unencrypted or bounded encrypted PKCS#8), non-CA certificate, and optional
ordered issuer PEM. Wrong passwords, tampering, changed selection, mismatch,
unsupported profiles, malformed inputs, stale UI operations, and worker
timeout request no download. Neither path writes Inventory or Vault.

The one-shot PFX worker receives bounded transferred buffers only after
readiness. The authenticated gateway denies worker network connections and
the file-reading script has no network/storage/markup-injection capability.
Best-effort buffer clearing and browser download restrictions do not promise
memory erasure, private filesystem permissions, no overwrite, or protection
from a malicious extension or compromised host. A release still requires
independent security audit.

Guarded by `TestCreateInspectExtractAndRefuse`,
`TestCreatePFXFromEncryptedKey`, `TestEncryptedPFXCreationRefusesUnsafeInputs`,
`TestWorkbenchSeparatesFileAndNetworkCapabilities`, and
`TestInitialLoginIsSetupOnlyUntilPasswordChange`, plus
`scripts/test-browser-pfx.mjs` and
`scripts/test-workbench-pfx-worker.mjs` and
`scripts/test-workbench-pfx-ui.mjs`.

## C62 — Private-key display is explicit, transient and separate

Normal summaries contain no private key. A separate eye action requires fresh
file authentication for encrypted PKCS#8/PFX and binds the inspected identity.
Plaintext input needs renewed screen-exposure consent, not a fake password.
Viewing adds no download, clipboard, logging, storage or network capability.
Text is cleared after 30 seconds and at page/tool/source boundaries; pending
operations are cancelled to prevent revival. Only one view is visible; print
CSS excludes it. Saved Vault keys need future separate instance reauthentication.
Screen capture, extensions and runtime copies remain residual risks.

Guarded by `TestPFXRevealReauthenticatesAndMatches`,
`TestPFXRevealRefusesUnsafeInputs`,
`TestWorkbenchSeparatesFileAndNetworkCapabilities`,
`TestWorkbenchPrivateViewHasNoPersistenceOrDownload`, plus
`scripts/test-browser-pfx.mjs`, `scripts/test-workbench-private.mjs`,
`scripts/test-workbench-pfx-ui.mjs` and `scripts/test-workbench-secret-view.mjs`.

## C63 — Offline key + CSR work is bounded and never issuance or trust

New RSA/ECDSA keys use crypto/rand and leave the worker only encrypted as
PKCS#8 in a ZIP with the public signed CSR; the ZIP is not encrypted. Existing
supported keys produce only a CSR. Every request is reparsed, signature-checked
and subject/SAN/public-key checked under the modern policy. Import consumes one
complete PEM/DER request at most 64 KiB; unknown attributes/extensions, ignored
email/URI names, duplicate/malformed names and weak signatures fail closed.
Public export binds the full displayed request fingerprint. Returned-certificate
comparison separately reports canonical public-key identity, literal SAN
differences, subject encoding/value changes and CA status, with trust false.
A fake certificate can copy a public key; issuer/chain/time/purpose/revocation
and deployment must not be inferred. One-shot worker deadlines, selection and
page cancellation prevent stale downloads; secrets never enter UI persistence,
network, clipboard, logs or public summaries.
Both directions reject foreign/missing dedicated-worker event metadata before
initialization or secret transfer; this is not a Window message allowlist.
Browser/OS copies and actual
download permissions remain outside the best-effort memory-clearing claim.

Guarded by `TestGenerateEncryptedKeyAndSignedCSR`,
`TestExistingKeyCSRFormatsAndEncryptedInput`,
`TestCSRFromAllSupportedExistingKeyFamilies`,
`TestLargeDERCSRPublicExportPreservesSignedRequest`,
`TestReturnedCertificateComparisonDoesNotImplyTrust`,
`TestCSRRefusesMalformedUnsafeAndIgnoredFields`,
`TestCSRNameSubjectPasswordAndFormatRefusal`, `FuzzInspectCSR`,
`TestWorkbenchCSRBoundaryIsExplicit`,
`TestWorkbenchHasNoNetworkOrProcessImports`, plus
`scripts/test-browser-csr.mjs`, `scripts/test-workbench-csr-ui.mjs` and
`scripts/test-workbench-csr-worker.mjs`.

## C64 — Saved-certificate reminders bind one server instant and fail visibly

After ready-session/revision/image authentication, inventory reads derive
date-only expiry from one UTC whole-second server instant. Reads do not change
generation or ciphertext. Exact NotAfter is expired; malformed or zero/reversed
ranges are invalid; long dates cannot saturate a duration. The API still omits
certificate bytes and explicitly says verification was not performed.

The page validates the whole response and agreement of every expiry field
before rendering. Missing/inconsistent metadata, malformed UTF-8/JSON, more
than 4 MiB, read timeout or refused authentication clears cards and pauses
automatic retries. Visible-page reads are minute-spaced and do not extend a
session or interrupt pending edits. Hidden/pagehide views clear metadata,
abort reads, discard late results and stop timers; BFCache return reauthenticates.
At 120 seconds the snapshot is stale, including during disabled refresh or an
open editor. Clock disagreement is warned about, never silently corrected.
7/14/30/90-day windows are local ephemeral views; expired/invalid/future records
always need attention. Reminder counts cover the entire snapshot, not only
the current search. There is no secret custody, outbound notification,
guaranteed closed-page alert, discovery, trust, renewal or Porch change.

Guarded by `TestObserveExpiryExactBoundariesAndNoTrust`,
`TestObserveExpiryRejectsMalformedAndHandlesLongDates`,
`TestInventoryMonitoringBindsOneServerClockAndNeverMutates`,
`TestLinuxInventoryAPIRequiresReadySessionAndExplicitSave`,
`scripts/test-rootwelld-inventory.mjs` and `scripts/test-inventory-demo.mjs`.

## C65 — Saved public handoff is exact, transient, and never implicit trust

Only an authenticated ready Linux same-origin native navigation can open one
saved public DER in Workbench. Mandatory Origin/fetch metadata, bounded exact
form fields, whole-image authentication, displayed generation and full
fingerprint lookup precede release. No query, key, credential, owner/location
note, new storage, write or session extension is introduced. The bounded
inert HTML payload is removed and reparsed against its fingerprint before
rendering. Manual replacement/page exit cancels pending processing and clears
saved-source state. Workbench still has no upload or persistence capability.
Guided Verify requires hostname/separate trust, never trusts a saved CA, and
can accept explicitly added bounded issuer files under unchanged verifier
policy. Browser/OS copies, already-open local snapshots, compromised code and
authenticated filesystem rollback remain residual risks (ADR 0042).

Guarded by `TestWorkbenchSelectionIsExactBoundedAndNonUploading`,
`TestInventoryWorkbenchHTMLContainsOnlySelectedPublicObject`,
`TestLinuxInventoryWorkbenchRequiresAuthorityAndExactSnapshot`,
`TestWorkbenchSeparatesFileAndNetworkCapabilities`,
`scripts/test-inventory-workbench.mjs`, `scripts/test-rootwelld-inventory.mjs`
and `scripts/test-inventory-demo.mjs`.

## C70 — ACME setup checking grants no network, storage or issuance authority

The fixed staging setup route accepts only bounded strict provider/challenge/
domains JSON from a ready, current same-origin session. It rejects malformed,
duplicate/unknown/secret fields, unsupported profiles/proofs/names and HTTP-01
wildcards. It does not resolve domains, connect to a CA, generate a key/CSR,
accept terms, save settings or provision challenges. All response execution
capabilities remain false; syntax success is not ownership or CA eligibility.
The UI rejects mismatched or capability-granting responses and clears pending
results on input change, hiding, navigation, deadline and Clear. This regression
boundary is not a sandbox or independent audit; future network/account work
requires its own reviewed authority and recovery gates.

Guarded by `TestACMEPlanChecksSyntaxWithoutGrantingCapabilities`,
`TestACMEPlanJSONIsBoundedStrictAndSecretFree`,
`TestACMEPlanGateHasNoCAOrPersistenceCapability`,
`TestACMESetupHasNoOutboundOrPersistenceImports`, `FuzzACMEPlanRequestJSON`
and `scripts/test-acme-setup.mjs`.

## C71 — Staging directory reachability cannot become enrollment or arbitrary egress

Only a ready, same-origin, explicitly confirmed request can enter the separate
Linux/Docker directory connector. Native Windows/macOS refuses before DNS and
cooldown because platform verification may fetch certificate objects. One fixed-host secret-free GET with system TLS/SNI,
validated public DNS pinned to numeric dialing, no proxy/redirect/retry, bounded
time/headers/body/parser and global cooldown/concurrency. Known endpoint URLs
are preflighted, never followed. No account/key/terms/order/storage capability;
fixed output and errors, no CA metadata reflection. Late invalid sessions or
contexts cannot publish success. Setup/offline Workbench cannot import the
connector. Already-sent traffic cannot be recalled after logout; reachability
does not prove issuance or certificate trust.

Guarded by `TestDirectoryDiscoveryUsesOnePinnedTLSGETWithoutSecrets`,
`TestDirectoryRefusesPrivateMixedDNSAndRevokedConsentBeforeDial`,
`TestDirectorySpecialAddressesAreDenied`,
`TestDirectoryResponseRefusalsNeverRetryOrReflect`,
`TestDirectoryStrictBoundedParser`,
`TestDirectoryTransportCannotFollowEndpointsOrSendTwice`,
`TestDirectoryConsentStrictlyRefusesUnconfirmedOrSecretInput`,
`TestDirectoryGateRequiresReadyOriginConsentAndThrottlesWithoutStorage`,
`TestDirectoryGateRejectsSetupAndLateSessionOrContext`,
`TestDirectoryInFlightLogoutRefusesResultAndConcurrentCheck`,
`TestStagingLivePlatformBoundary`,
`TestDirectoryNativePreviewRefusesBeforeCooldownOrConnection`,
`TestWorkbenchHasNoNetworkOrProcessImports`, `FuzzStagingDirectory`,
`FuzzDirectoryConsent` and `scripts/test-acme-directory.mjs`.

## C69 — Saved-key attachment never overwrites or silently transfers a secret

ADR 0048 permits only adding a strict key to an authenticated public-only
certificate record under exact generation/fingerprint. Existing legacy/material
keys refuse replacement. The writer repeats the check and requires explicit
sealed acknowledgement for mismatch; Save additionally requires fresh instance
password through the shared attempt/concurrency budget. Certificate, supplied
bundle, order, import provenance and notes remain intact. Limits refuse with
no partial image; atomic history/full restore preserve the attachment.

Browser Check is optional, but Save revalidates. File identity/reread digest,
preview lifetime and generation bind the choice; changed/hidden/cancel/deadline
state clears owned secrets and discards late output. Transmitted Save may still
commit; uncertainty is shown, not claimed rollback. Fixed errors prevent raw
secret reflection. The existing native Convert handoff contains selected public
DER only and requires actual WASM identity reinspection; key/bundle/notes/trust
are never auto-transferred. Key/PFX conversion needs explicit encrypted export
and file selection. No CA/network/production claim follows.

Guarded by `TestAttachKeyPreservesRecordAndRefusesOverwrite`,
`TestAttachEncryptedKeyAndCapacityRefusals`, `TestKeyAttachmentRequestModesAreStrict`,
`TestLinuxSavedKeyRequiresFreshAuthenticationAndPreservesRefusedImage`,
`TestLinuxMaterialMismatchExportAndBundleFullRestore`,
`TestLinuxInventoryWorkbenchRequiresAuthorityAndExactSnapshot`,
`scripts/test-saved-key-attachment.mjs` and `scripts/test-inventory-workbench.mjs`.

## C66 — Bulk preview is local and Save is exact and atomic

Inventory public bulk preview does not upload selected bytes. Save is explicit,
requires a current successful duplicate-free preview and rereads exact files
against all ordered fingerprints. Only the reparsed canonical public PEM plus
shared manual notes enters one existing authenticated atomic append request.
All-or-nothing duplicate/private/malformed/capacity refusal is unchanged.
Late/changed/hidden source work cannot initiate POST or restore preview. Saved
duplicates are explained, not silently skipped. No new trust, formats, private
custody or outbound destination is granted. After a sent request, an uncertain
outcome requires refresh, not an assertion that nothing was saved. ADR 0043
records bounds, advisory snapshot semantics and browser residual risks.

Guarded by `TestInventoryBulkAssetsRemainBehindReadyAccess`,
`TestLinuxInventoryAPIRequiresReadySessionAndExplicitSave`,
`scripts/test-inventory-bulk.mjs`, `scripts/test-rootwelld-inventory.mjs`
and `scripts/test-inventory-demo.mjs`.

## C67 — Public lifecycle comparison/history and background checks stay scoped

An exact generation/fingerprint ready-session request releases one saved
public DER, never notes or keys. A single bounded local candidate is reparsed
and compared in actual Go WASM without upload, save, replacement or trust.
SAN/key/issuer/date changes remain informational. Changed/hidden/refreshed
sources and late results fail closed; response sizes and errors are bounded.

Every successful inventory mutation commits one authenticated encrypted event
in the same complete image; rejected mutations commit neither. Fixed actions,
UTC seconds, contiguous generations and unique fingerprints are validated
before any records/events are released. History includes no prior notes, DER
or credentials. Full snapshot/restore retains it. Legacy history is unknown;
1024 events refuse additional writes rather than erase old activity. This is
not an independent audit log or rollback anchor, and downgrade is not supported
after new writes. Deleted identities remain in history and backups.

The daemon independently checks once per minute using only an existing ready
session key, with no lifetime extension or persisted monitoring credential.
The RAM-only 30-day inbox clears on revocation/expiry/revision/storage/clock
failure; logout during a read cannot publish a late result. Observation age,
generation and unlock deadline are reported and stale observations are not
healthy. Closing a page does not stop this worker, but logout, restart or the
12-hour session limit require another unlock. No external alerts, 24/7 service,
live discovery, renewal, private custody or Porch change is claimed (ADR 0044).

Guarded by `TestComparisonTracksAllNamesKeyAndDatesWithoutTrust`,
`TestComparisonRefusesPrivateMixedBundlesAndMalformed`, `FuzzPublicComparison`,
`TestHistoryIsAtomicEncryptedCompleteAndRetainsDeletionIdentity`,
`TestHistoryLegacyBoundaryContinuityCapacityAndContext`,
`TestBackgroundMonitorWithoutBrowserExpiresClearsAndRejectsLateLogout`,
`TestBackgroundMonitorInvalidRevisionClearsSessionsAndLateResult`,
`TestLinuxInventoryAPIRequiresReadySessionAndExplicitSave`,
`TestLinuxInventoryDurableImportAndFreshFullRestore`,
`TestInventoryBulkAssetsRemainBehindReadyAccess`,
`scripts/test-inventory-lifecycle.mjs`, `scripts/test-rootwelld-inventory.mjs`
and `scripts/test-inventory-demo.mjs`.

## C68 — One certificate library does not collapse the secret boundary

ADR 0046 supersedes earlier no-custody statements only for the separate
certificate-library API. Offline Workbench/public bulk import still reject
secret-bearing public input. Ready Linux sessions may explicitly Check/Save
one certificate and an optional mathematically matching non-CA private key.
Files, JSON and KDF concurrency are bounded; Save revalidates identity and
generation. Check is an own-daemon upload and performs no write or trust verdict.

One complete authenticated atomic image contains public record and separately
AES-GCM-sealed, HKDF-purpose-separated attachment. Every attachment authenticates
and matches a unique certificate before any list/history output. Public output
contains key-presence only. Metadata updates preserve the key; deletion removes
both from current image; full restore retains the pair. Legacy public images
remain readable; old binaries refuse attachment-bearing images.

Private download requires fresh instance password under the shared attempt
budget, exact session revision/generation/fingerprint and a final session check.
Only encrypted PKCS#8 key in an unencrypted ZIP is exposed here; no plaintext
custody export/reveal. Separate output-password policy is mandatory. Browser
selections must be checked before Save; changing/hidden/late/uncertain work
cannot restore authority. Untrusted parser/network/file error text is never
rendered. Backups are manual; old images, compromised hosts, runtime copies and
authenticated rollback remain risks, not erased by this UI simplification.
This is single-operator development custody, not audited production or RBAC.

ADR 0047 supersedes the preceding matched-only import/export scope: the new
material attachment holds one selected certificate, its bounded related public
bundle and optional strictly parsed key. Check is optional in the UI; Save
always revalidates. A computed mismatch is retained only with explicit sealed
acknowledgement, not labeled unchecked or matched. Ambiguous selection requires
an exact supplied fingerprint; issuer signatures are not trust. Material
authentication recomputes selection/status before any metadata output; note,
delete and full restore preserve/remove/restore the attachment as a whole.
Legacy matched-key attachments still require match. Matched-pair downloads
refuse mismatch; encrypted key-only download has the same fresh-password,
attempt-limit and strong separate-password gates. Included public bundle export
does not establish trust. A distinct Inspect secret picker uses a one-shot
offline worker with no save/export/network capability; malformed/password errors
are never mismatch results. Public pickers still refuse secret-bearing input.

Additional guards: `TestBundleSelectionMatchMismatchAndIssuerRefusals`,
`FuzzBundleMatchRefusesMalformedKey`,
`TestMaterialMismatchAcknowledgementPreservationAndTamper`,
`TestLinuxMaterialMismatchExportAndBundleFullRestore`,
`scripts/test-key-match-ui.mjs` and actual key-match Go WASM assertions in
`scripts/test-browser-csr.mjs`.

Guarded by `TestPrepareCertificatePairsAndRefusals`,
`TestEncryptedKeyPairRequiresCorrectPassword`,
`FuzzPrepareRefusesSecretInCertificate`,
`TestCertificateKeyCustodyAtomicityPreservationAndDeletion`,
`TestAttachmentTamperAndIdentitySwapFailBeforeOutput`,
`TestCertificateRequestModesRejectMalformedAndAmbiguousJSON`,
`TestLinuxCertificateLibraryCustodyDownloadAndFullRestore`,
`scripts/test-certificate-library.mjs`, `scripts/test-rootwelld-inventory.mjs`
and `scripts/test-inventory-demo.mjs`.
