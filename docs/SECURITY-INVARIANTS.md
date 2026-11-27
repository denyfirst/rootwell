# Security invariants

An invariant is a behavior Rootwell must preserve, not an aspiration. Every
entry names tests that exist. A change that renames or removes a cited test must
update this file in the same commit, and CI verifies that the citations resolve.

This list guards the CLI, certificate-inspection, offline TLS verification,
and certificate/private-key match boundaries. File-writing invariants are
added with the code that first creates those risks.

## C116 — A request's new key is made and kept in the vault, joins only its own certificate, and a renewal is bookkeeping (ADR 0091)

`POST /api/requests/create` needs a signed-in session, the exact Origin and
the page header. It takes a key kind (`ec-p256`, `rsa-2048`, `ec-p384`,
`rsa-3072` or `rsa-4096`) with either DNS names and IP addresses and optional
organization details, or `renews` and the fingerprint of a saved certificate,
and nothing else: an unknown field, a key or a password is refused. The names
are checked as the browser's request maker checks them (C63). `rootwelld`
makes the key with `crypto/rand`, one at a time, and keeps it in a sealed
record of its own, apart from the request, under an index that is an HMAC of
the key's public fingerprint (C107). No answer, list or log carries the key:
the page gets the request, which is public. At most 50 requests wait; a
stale page gets 409 and nothing is kept.

A renewal takes the certificate's DNS names, IP addresses, common name when
it is one of them, and its organization, locality, province and country, and
always a new key. One renewal waits per certificate; a certificate replaced
already, an authority or one with no names gets none.

Saving a certificate whose public key is a waiting request's saves the
request's key with it, after the same match check as a chosen key, and
deletes the request and its key in the same write; a key sent with it is set
aside. A finished renewal marks the certificate it renews replaced and gives
the new one its places and, when it has none, its owner, unless that one was
deleted or replaced meanwhile; end dates are not compared, since an early
renewal may end first. Any other replacement
needs the person's choice (`replaces`) and an older certificate that is
saved, not replaced, not an authority, names something, has every name the
newer one has, and ends first; otherwise 409 and nothing is saved. A replaced
certificate keeps its key and record; deleting its successor makes it current
again. Replaced is the person's record, never a claim about what a server
serves.

`POST /api/requests/delete` gives up a request and deletes its key only after
a fresh code (C111); without one it answers 428 and keeps both.

On the Request page, `request.js` reads key files and makes no request;
`request-keep.js` sends the typed names to `/api/requests/create`, after
`/api/inventory` for the list's count, and touches no file, worker or page
element.

Guarded by `TestGenerateKeptChecksLikeTheBrowser`,
`TestARequestKeepsItsKeyUntilItsCertificateFinishesIt`,
`TestARenewalTakesTheOlderCertificatesPlace`,
`TestAnEarlyRenewalThatEndsSoonerStillTakesThePlace`,
`TestACertificateWithAKeyGoCannotReadIsStillSaved`,
`TestAChosenReplacementMustCoverTheNamesAndLastLonger`,
`TestARequestNeedsItsOwnKeyAndGivingItUpDeletesTheKey`,
`TestARequestRecordIsReadStrictly`,
`TestLinuxARequestKeepsItsKeyAndItsCertificateFinishesIt`,
`TestLinuxARenewalIsMadeFromTheCertificateAndTakesItsPlace`,
`TestLinuxGivingUpARequestNeedsAFreshCode`, `TestLinuxRequestInputIsRefused`,
`TestPagesSeparateFileAndNetworkCapabilities`,
`scripts/test-certificates.mjs` and `scripts/test-request.mjs`.

## C115 — A chosen file is read by what it holds, and nothing in it is skipped (ADR 0089)

Add, Inspect and Convert read each chosen file with the engine's
`readFile`, never by its name: a PFX named `.bin` is a PFX. A file is a PFX,
certificates, one private key, or certificates with their key; each part
goes on in the strict form the existing readers and the server already
accepted, and the server's accepted input is unchanged. Beyond those forms a
file may carry a UTF-8 byte order mark, CRLF lines and printable text between
PEM blocks (OpenSSL's "Bag Attributes", "subject=" and "issuer=" lines), a
DER or PEM PKCS#7 certs-only bundle, an `EC PARAMETERS` block for its EC
key's own named curve, and an old OpenSSL `Proc-Type: 4,ENCRYPTED` RSA or EC
key with DES-EDE3-CBC or AES-CBC. Base64 inside a block stays strict. An
unknown block, a second key, a broken or unterminated block, a stray boundary
line, control characters, explicit or other-curve EC parameters, a P7B with
signers, content, revocation lists, attribute certificates, BER, more than 64
or duplicate certificates, and more than 16 MiB refuse the whole file, and
the page names the file that was wrong. An old-style key is opened only with
its password, by the standard library's reader of the format, after its
headers, cipher, size (64 KiB) and password (256 bytes) are checked; a wrong
password is named as wrong. Rootwell never writes that format. Inspect gives the key of a combined
file only to its one-shot key check and never shows it; Add sends it to the
server's existing key check as it would a chosen key file.

Guarded by `TestSplitReadsWhatToolsWrite`, `TestDecryptBoundsThePassword`,
`TestSplitRefusesAndNamesTheProblem`, `TestUnlockOpensOldStyleKeys`,
`TestKeyPreparesKeyFilesForTheStrictReaders`, `FuzzSplit`,
`TestParseReadsCertsOnlyBundles`, `TestParseRefusesWhatItDoesNotUnderstand`,
`FuzzParseCertsOnly`, `TestParseReadsOpenSSLBundles`,
`TestDecryptOpensEveryCipherWithItsPassword`,
`TestDecryptRefusesWhatItDoesNotRead`,
`TestDecryptAgreesWithTheStandardLibrary`, `FuzzDecryptLegacyKey`,
`TestDecryptOpensOpenSSLTraditionalKeys`, `TestIsPFXRecognisesContentNotName`,
plus `scripts/test-browser-wasm.mjs`, `scripts/test-certificates.mjs`,
`scripts/test-inspect.mjs` and `scripts/test-convert.mjs`.

## C114 — A backup holds no key and opens only with the key it was made under; restore keeps only what opens; rotation leaves the old key nothing in the current vault (ADR 0088, RW-04)

The Installation page downloads a backup with `POST /api/backup`, which
needs a signed-in session, a fresh code (C111), the exact Origin and the
custom header; GET, another site and a session without a fresh code get
405, 403 and 428, and nothing is copied. The server copies the whole vault in
one bbolt read transaction while Rootwell keeps running, so the copy is
consistent, and writes it as a compacted file of the live records only:
pages bbolt freed, such as a deleted key or a record sealed under an earlier
key, never go out. One backup is made at a time, and it goes only to the
session that asked, still signed in. It is sent as
`rootwell-backup-<UTC time>.db` and holds every live record as the vault
holds it, all sealed (C107): certificates, keys, accounts,
passkeys and Rootwell's certificate authority. It holds no instance key and
no plaintext, so it opens only with the key the vault had when it was made.
A vault larger than 64 MiB gets 507 and is copied on the server with the
service stopped. `GET /api/installation` gives a signed-in page the covered
names, the authority's fingerprint, when the server certificate ends and how
many certificates are saved, and changes nothing.

`rootwelld restore <backup-file> <data-dir> <key-file>` writes only into an
empty data directory, made `0700` if it is missing, so it never replaces an
installation. It copies the backup to a temporary file there, syncs it, and
renames it into place; it keeps the vault only if it opens with the key, and
otherwise removes it, so a refused restore leaves nothing. Without a key
file, it reads the instance key's recovery code at the terminal, and writes
the key file from it only after the restored vault opens with it.

`rootwelld key-rotate <data-dir> <key-file>` checks the key's directory, then
shows the new key's recovery code and changes nothing until the person types
`SAVED`. It writes the new key beside the old one as `<key-file>.new`. Then,
in one transaction, it seals every record again under a new data key wrapped
by the new key, and seals the index and one-time-code keys in the meta record
under it, so record IDs and the digests of setup and recovery codes stay as
they were. bbolt keeps the pages it replaced until they are reused, and those
held every record under the old key, so with the vault closed the command
rewrites the file with its live records only. Last, it renames the new key
file over the old one. Afterwards the vault refuses the old key, a damaged
sealed key too, and nothing left in the file opens with the old key; a vault
never rotated opens as before. If the transaction reports an error, the new
key is kept when the vault opens with it, and removed only when it does not. A `.new`
file left by an interrupted rotation is named and never overwritten: the next
rotation refuses and says how to finish.
`rootwelld key-export <data-dir> <key-file>` prints the recovery code of the
key file only after the key opens the vault. `key-rotate` and `key-export`
refuse while `rootwelld serve` holds the vault, and all three commands refuse
a key file inside the data directory and need an interactive terminal (C44,
C107).

Rotation cannot reach copies made before it: such a backup still opens with
the old key and its old recovery code only. The index and code keys are kept
rather than made again, so the old key still derives them, and with the
current file it can tell whether a certificate it already knows is kept
there; it opens no record.


The vault keeps records confidential, not fresh: someone who can write
`rootwell.db` without the key can put an older sealed record back, such as an
earlier password hash or a spent recovery code. The operating system keeps
the file writable by the service user only (C107).

Guarded by `TestRotationMovesEverySecretToTheNewKey`,
`TestADamagedSealedIndexKeyIsRefused`,
`TestABackupIsAWholeVaultThatOpensWithItsKey`,
`TestNothingSealedBeforeARotationStaysInTheFileOrItsBackups`,
`TestOneBackupAtATimeAndOnlyToTheSessionThatAsked`,
`TestLinuxInitShowsNoCodeForAKeyDirectoryOthersCanRead`,
`TestABackupNeedsAFreshCodeAndOpensWithTheInstanceKey`,
`TestTheInstallationPageSaysHowBrowsersReachRootwell`,
`TestLinuxKeyExportPrintsTheCodeOfTheKeyThatOpensTheVault`,
`TestLinuxKeyRotationNeedsSAVEDAndLeavesOnlyTheNewKey`,
`TestLinuxRestoreWritesABackupOnlyIntoAnEmptyDirectoryAndOnlyIfItOpens`,
`TestOfflineCommandClassificationAndNoSecretArgv`,
`TestPagesAndScriptsNeedASignInAndWorkersReachNoNetwork` and
`scripts/test-rootwelld-auth.mjs`.

## C113 — A passkey stands in for the phone code only for this site's name, a verified person and a one-time challenge (ADR 0088)

A passkey (WebAuthn) is an optional second factor beside the phone code. It
resists phishing: the browser lets it sign only for the name it was made on,
so a look-alike site gets nothing it can use. After the password, a passkey
stands in for the phone code; when signed in, it counts as a fresh code
(C111). The phone stays mandatory, and the phone and the recovery codes stay
the way back. That is also the limit: a person who has a passkey can still be
tricked into typing a phone code on another site.

An account keeps at most ten passkeys. Adding one, with an optional name of
up to 64 printable characters, or removing one needs a fresh code, counts a
revision of the account and ends its other sessions (C109). A setup code that
replaces an account's sign-in removes its passkeys too, since the device that
holds them may be lost (C108).

The relying party is the name in the request's Host: `localhost` or a DNS
name added with `serving-names` (C112). Browsers allow no passkeys on an IP
address, so there the server refuses with 409 and the pages offer none. A
passkey made on one name does not work on another: one added on `localhost`
does not sign in on `rootwell.lan`.

Each ceremony gets a challenge of 32 random bytes, kept with the session in
memory, for one purpose (sign-in, fresh code or adding a passkey). It is good
for two minutes, and the first answer uses it up, right or wrong.
`internal/passkey`, in the tree with no new dependency, then checks:

- the browser's record: the right ceremony, this challenge, an origin of
  exactly `https://` and the Host, and not from inside another site's page;
- the authenticator's data: made for this name, with the person present and
  verified by a fingerprint, a face or a PIN;
- the key: ES256, Ed25519 or RS256 of 2,048 to 8,192 bits, nothing else;
- the signature, by the passkey the account added, over that data and the
  browser's record;
- the signature count: where the authenticator keeps one, a count that does
  not grow is refused, since the passkey may have been copied.

Attestation is neither asked for nor trusted: any format is accepted and its
statement is never read. A passkey proves only that the authenticator added
earlier signs again, for this name, after the person unlocked it. The
authenticator's CBOR is read strictly: definite lengths only, no tags or
floats, at most 8 levels and 64 items, and no duplicate keys. The account
record keeps each passkey's ID, public key, algorithm, count, name and dates;
its private key never leaves the authenticator. The WebAuthn user ID is an
HMAC of the account name under the vault's index key, so it says nothing
about the name. Only a session past the password learns whether the account
has a passkey and which IDs it may use. A refused answer counts as a wrong
code (C109, C110).

Guarded by `TestEachAlgorithmRegistersAndSignsIn`,
`TestTheBrowsersRecordMustBeThisCeremonyOnThisOrigin`,
`TestTheAuthenticatorMustBeForThisNameAndVerifyThePerson`,
`TestOnlyTheThreeAlgorithmsAreAccepted`,
`TestOnlyASignatureOfThisChallengeByThisPasskeyCounts`,
`TestACountThatDoesNotGrowIsRefused`, `TestCBORIsReadStrictly`,
`FuzzDecodeCBOR`, `FuzzVerifyRegistration`,
`TestPasskeysSignInAndStandInForAFreshCode`,
`TestPasskeyAnswersAreBoundedAndNamed`,
`TestPasskeysAreAddedUsedAndRemovedWithTheirRevisions` and
`scripts/test-rootwelld-auth.mjs`.

## C112 — Rootwell answers only over TLS 1.3, only to its covered names, and its authority signs only for them (ADR 0088)

`rootwelld serve` speaks HTTPS only, with TLS 1.3 only. Go's defaults choose
the key exchange, the hybrid post-quantum X25519MLKEM768 first. A TLS 1.2
client is refused, and plain HTTP to the port gets nothing usable. The server
listens on port 4180 of `127.0.0.1` and `[::1]` (C33), and on each
`--listen <address>` as well. A `--listen` address must be an IP address the
certificate covers: a loopback, unspecified (`0.0.0.0`, `::`) or multicast
address, a name, or an address it does not cover refuses the start. Rootwell
never listens on every address.

The covered names are `localhost`, `127.0.0.1` and `::1`, always, and the
names added with `rootwelld serving-names`: IP addresses, or DNS names of at
least two labels, such as `rootwell.lan`; no wildcards, and no one-word name
but `localhost`, since a limit for `lan` or `com` would cover every name below
it. At most 16 names in all. Every request must come over TLS and carry
one of them with `:4180` as its Host; any other name, port or spelling gets
400, so a rebound DNS name or another port reaches nothing (audit RW-02).
Every change must carry an Origin of exactly `https://` and that same Host, so
a page on one name cannot act on another. A name that is not loopback gets
HSTS for a year, without subdomains; loopback names get none, because on
`localhost` it would force HTTPS on every other local port of the machine.

The first start makes Rootwell's own certificate authority in the vault, one
sealed record with its key (C107): P-256, ten years, name-constrained to the
covered names, path length zero, and for server certificates only, so its key
cannot sign for any other name. A DNS limit also covers the names below it,
so the authority excludes those too: its key cannot sign for
`mail.rootwell.lan` either. Only a covered name with another covered name
below it keeps its subdomains, or that other name would be refused. It signs a 90-day P-256 server certificate for
exactly those names. The running server checks every six hours and replaces
that certificate 30 days before it ends, or when it no longer matches the
names, without a restart; it writes to the vault only then.
`/rootwell-ca.pem` gives the authority's certificate to anyone, and every
start prints its SHA-256 fingerprint, so a person trusts it once, after
comparing the two. `serving-names <data-dir> <key-file> [name]...` runs only
with the service stopped and replaces the added names; with none it goes back
to the loopback names. It always makes a new authority, since an authority's
names are fixed, and prints the new fingerprint: browsers must trust the new
one. A refused name changes nothing. It prints no secret, so it needs no
terminal (C44).

The authority is trusted only where a person trusted it, and publishes no
revocation list. On `localhost`, browsers share cookies with every other local
port, so another web server opened there may receive the session cookie; a
name of Rootwell's own keeps it apart (RW-02).

Guarded by `TestOnlyHTTPSToTheConfiguredNamesIsServed`,
`TestTheServerSpeaksTLS13OnlyAndTheAuthorityVerifiesIt`,
`TestListenTakesOnlyCoveredHostAddresses`,
`TestListenLoopbackHoldsBothAddresses`,
`TestLinuxServingNamesMakeANewAuthorityForThoseNames`,
`TestOfflineCommandClassificationAndNoSecretArgv`,
`TestTheFirstStartMakesAnAuthorityForThisHostOnly`,
`TestTheServerCertificateIsReplacedAMonthBeforeItEnds`,
`TestNewNamesMakeANewAuthority`,
`TestTheAuthorityKeyIsSealedAndTheRecordReadStrictly`,
`TestNamesAlwaysIncludeLoopbackAndRefuseBadInput`,
`TestTheServerCertificateVerifiesForEveryNameAndNothingElse`,
`TestTheAuthorityCannotSignForOtherNames`,
`TestANameBelowAnotherStillVerifies`,
`TestRenewalIsDueBeforeTheEndOrWhenNamesChange`,
`TestTheFingerprintReadsLikeABrowserShowsIt`,
`TestThePackageOpensNoSocket` and `scripts/test-container-volume.sh`.

## C111 — A key leaves, a key is deleted, or sign-in changes only after a fresh code (ADR 0088)

A signed-in session is fresh for ten minutes after a phone code, a recovery
code or a passkey (C113). Signing in counts, and so does a code entered in
the dialog that sends it to `/api/fresh`, or a passkey used from its
**Use a passkey** button. Without a fresh code the server answers 428 and
does nothing when asked to:

- download a key, with its certificate or alone: in the ZIP for nginx and
  Apache, in a PFX for Windows and IIS, or by itself, always locked with the
  download password (20 to 128 printable characters); a PFX leaves out the
  self-signed root and holds RSA and ECDSA keys only;
- delete a certificate that has a saved key (audit RW-10), or give up a
  request whose new key Rootwell keeps (C116);
- change the password, move to a new phone, make new recovery codes, or add
  or remove a passkey;
- download a backup of the whole vault from the Installation page (C114).

The Certificates, Account and Installation pages then ask for a code in a
dialog (`fresh.js`) and send the same request once more; Cancel changes
nothing.
Nothing else asks: a public download, notes, adding a key to a saved
certificate and deleting a certificate without a key need only a signed-in
session. No request asks for the account password again, except a password
change, which also needs the current one; the certificate API refuses a
password field. A wrong code in the dialog counts as a failure (C110), five
end the session, and a recovery code used there is spent. A fresh code moves
the session to a new token, so a copy of the old token, taken earlier, gains
nothing from it.

Guarded by `TestAFreshCodeGuardsChangesToHowTheAccountSignsIn`,
`TestAFreshCodeMovesTheSessionToANewToken`,
`TestPasskeysSignInAndStandInForAFreshCode`,
`TestABackupNeedsAFreshCodeAndOpensWithTheInstanceKey`,
`TestLinuxCertificatesLiveInTheVaultAndSurviveARestart`,
`TestLinuxACertificateWithoutAKeyIsDeletedWithoutAFreshCode`,
`TestCertificateRequestsRefuseAPasswordField`,
`TestLinuxAPFXForWindowsHoldsTheChainAndTheKey`,
`TestLinuxGivingUpARequestNeedsAFreshCode`,
`scripts/test-certificates.mjs` and `scripts/test-rootwelld-auth.mjs`.

## C110 — Only failures count, per known device or per name and source (ADR 0088)

A wrong password, phone code, recovery code or passkey answer counts against
the account name, which allows 5, and against the source address, which
allows 20; an IPv6 address counts by its /64. A wrong setup code counts
against its source address only: the code is 120 random bits, and nobody
guessing from elsewhere can keep the owner from setting up or recovering.
Each failure past the allowed ones makes the next try wait: one minute, then
twice as long each time, up to fifteen. A waiting name, address or device
gets 429 with `Retry-After`, and nothing is checked.

Each try counts as a failure before it is checked, under one lock, and is
given back when it succeeds, or fails for a reason that is not the guess,
such as a busy server. Tries sent together therefore cannot all pass before
one is counted: a session takes at most five wrong codes however they
arrive, and a right code cannot bring back a session that wrong codes ended
meanwhile.

**Known devices.** A browser that signs in completely, with a code or a
passkey after the password, also gets the cookie `__Host-rootwell_device`:
256 random bits, Secure, HttpOnly, SameSite=Strict, path `/`, for 30 days.
The account keeps only its SHA-256, for at most ten devices, in its sealed
record. Every complete sign-in replaces the browser's device cookie, and a
password change or a setup forgets every device. While a request carries a
device cookie the account knows, its failures count against that device
alone, which allows 5, and not against the name or the address. So guesses at
the name from anywhere, or failures from the owner's own address (everyone on
the server itself shares `127.0.0.1`), cannot lock the owner out of a browser
that signed in before. Two device cookies count as none. The device cookie
opens nothing; it only chooses which limit counts.

A success costs nothing (audit RW-07): a complete sign-in or a fresh code
forgets the name's failures, and failures are forgotten an hour after the
last. The table holds 4,096 names and addresses; when every entry is waiting
out a lock, a name or address not yet counted waits a minute rather than
anyone's lock being forgotten. One password check (Argon2id, 64 MiB) runs at
a time; a request waits up to five seconds for it, and a busy answer is not a
failure.

Guarded by `TestOnlyFailuresCountPerNameAndPerSource`,
`TestAFullFailureTableHoldsNewNamesRatherThanForgetALock`,
`TestCodeGuessesSentTogetherAreCountedOneByOne`,
`TestARightCodeDoesNotReviveAnEndedSession`,
`TestTheOwnerSignsInAsSoonAsAWaitEnds`,
`TestAKnownDeviceIsNotLockedOutByOthers`,
`TestSetupGuessesCountOnlyAgainstTheirSource`,
`TestFiveWrongNewPhoneCodesEndTheSession`,
`TestDevicesAreKnownForAWhileAndForgottenWithThePassword` and
`scripts/test-rootwelld-auth.mjs`.

## C109 — Sign-in takes a password and a one-time code, and sessions stay short and in memory (ADR 0088)

Sign-in has two steps: the name and password, then, within five minutes, a
six-digit phone code (RFC 6238: SHA-1, 30 seconds, one step of drift either
way) or one recovery code; a passkey the account added may stand in for the
phone code (C113). A phone code is refused once its step, or a later one,
has been used; a recovery code is taken off the list when it is used.
Until both steps pass, a session reaches only the sign-in endpoints, never a
page, a script or the certificate API. A setup session has fifteen minutes to
confirm its phone, and reaches nothing else either.

A session token is 256 random bits. The server keeps only its SHA-256, in
memory, so a restart signs everyone out. The cookie is
`__Host-rootwell_session`: Secure, HttpOnly, SameSite=Strict, path `/` and no
domain. Every step, and every fresh code (C111), issues a new token and ends
the old one, and a request carrying two session cookies counts as having
none. A new token keeps the session's start, so the eight hours still count
from the sign-in. A signed-in session ends
after 15 minutes without use and 8 hours at most; a page asking for its
status (`GET /api/session`) is not use. Five wrong codes end a session. At
most 64 sessions are kept: when the table is full, an account's oldest
session makes room for its newest, and no other account's session is ended
for it.

Sign-out ends only its own session. A password change ends every session of
the account, this one too. Moving to a new phone, making new recovery codes,
adding or removing a passkey, or using a setup code for an existing account
ends every other session and gives this one a new token. The cookie travels
only over HTTPS (C112).

Guarded by `TestSignInTakesThePasswordThenACode`,
`TestCodesMatchRFC6238AndAreNeverAcceptedTwice`,
`TestSignInTakesThePasswordThenOneCodeOnce`,
`TestSessionsEndWhenIdleOrOldAndAStatusCheckIsNotUse`,
`TestTheSessionCookieIsHostOnlySecureAndStrict`,
`TestTheSessionTableIsBoundedWithoutEndingOtherAccounts`,
`TestAPasswordChangeEndsEverySession`,
`TestANewPhoneKeepsThisSessionAndEndsTheOthers`,
`TestNewRecoveryCodesReplaceTheOldOnes`,
`TestPasswordPhoneAndRecoveryChangesCountARevision`,
`TestPasskeysSignInAndStandInForAFreshCode`,
`TestCertificatesPageAndItsScriptsRemainBehindReadyAccess` and
`scripts/test-rootwelld-auth.mjs`.

## C108 — Accounts live in the vault, and only a setup code from the server makes or resets one (ADR 0088)

Each account is one sealed vault record (C107): its name, an Argon2id hash of
its password (64 MiB, three passes, four lanes), its phone key, the last
phone-code step it used, keyed digests of its recovery codes, the public keys
of its passkeys (C113), and a revision.
No name, password, phone key or recovery code reaches the disk in the clear,
and a record with an unknown field is refused. One-time codes are digested
under a key the vault derives for them alone, which differs between
installations. This release has one account (`MaxAccounts`).

A name is 1 to 64 letters and digits, with `.`, `-` and `_` allowed after the
first, and is compared without case. A password is at least 15 characters,
not a common one or a short pattern repeated, and at most 1,024 bytes: one
limit everywhere (audit RW-09). A wrong name gets the same answer, after the
same work, as a wrong password.

There is no default password and no open sign-up. `rootwelld init` prints a
setup code once the key's recovery code is saved, and `rootwelld setup-code`
makes a new one with the service stopped. A setup code is 120 random bits,
kept only as a keyed digest; it works once, for 24 hours, and a new one
replaces the last. Without a name it makes the first account and is refused
once one exists. With an account's name it works only for that name,
replaces the account's password and phone, and removes its passkeys, since
the device that holds them may be lost. The setup page checks the code,
the name and the password, then shows a new phone key as a QR code and as
text. The account is written only when the phone shows a right code, in the
same write that spends the setup code, so no account ever signs in with a
password alone. Ten recovery codes of 80 random bits are then shown once;
earlier ones stop working.

Guarded by `TestASetupCodeMakesTheFirstAccountOnce`,
`TestASetupCodeStopsWorkingAfterADay`,
`TestASetupCodeForAnAccountReplacesItsSignIn`,
`TestPasskeysAreAddedUsedAndRemovedWithTheirRevisions`,
`TestTheAccountIsSealedAndReadStrictly`,
`TestAnAccountRecordWithAnUnknownFieldIsRefused`,
`TestNamesAreComparedWithoutCase`, `TestPasswordsHashAndVerifyWithOneLimit`,
`TestTheCommonPasswordListIsThePinnedOne`,
`TestBootstrapCodesAreLongAndKeyed`, `TestRecoveryCodesWorkOnceInAnyCase`,
`TestNewSeedsDrawAsAuthenticatorQRCodes`,
`TestSetupSavesTheAccountOnlyOnceThePhoneIsConfirmed`,
`TestLinuxInitNeedsSAVEDAndLeavesAWorkingSetupCode`,
`TestLinuxSetupCodeMakesTheFirstAccountOrReplacesItsSignIn` and
`scripts/test-rootwelld-auth.mjs`.

## C107 — Certificates live in the vault, opened by an instance key kept apart (ADR 0088)

The Certificates page's list lives in `rootwell.db`, a bbolt file in the
private data directory. Every record is sealed with AES-256-GCM under its own
random key, which is wrapped under a key derived from the instance key with
HKDF-SHA256. Both seals are bound to the vault, the record's kind, its ID and
its revision, so a record moved, replayed at another revision or changed by
one byte is refused. Record IDs are HMACs of the fingerprint under another
derived key, so the file does not list domain names, and the same certificate
gets a different ID in another vault (audit RW-12). No plaintext, fingerprint
or name reaches the disk. A failed write keeps nothing. The certificate list
counts its own changes, in a record of its own, and every change names the
count the page read, so a stale page gets 409; a write outside the list, such
as a sign-in, leaves an open page current. A private key is a record of its
own: listing never opens one, and only a download borrows it (RW-11). The list
holds at most 500 certificates; nothing else limits how many writes the vault
takes (RW-01).

The instance key is 32 random bytes in a `0600` file of the service user, in
a private `0700` directory outside the data directory; `init`, `serve`,
`setup-code`, `key-restore`, `serving-names`, `key-export`, `key-rotate` and
`restore` refuse a key file inside it, so a copy of the data never carries
its key. Another key cannot open the vault. `rootwelld
init` never replaces a key file or a vault. It shows the key's recovery code
(`RW1-` and grouped base32 with a check) once, and makes the key file and the
vault only after the person types `SAVED`; then it prints a setup code for the
first account (C108). `rootwelld key-restore <data-dir> <key-file>` reads the
key's recovery code from the terminal and rebuilds a lost key file only after
the code opens the vault in that data directory. It writes nothing for a code from another
installation, while `rootwelld serve` holds the vault, or over an existing key
file. The vault opens only in a `0700` directory owned by the service user,
and one process holds it at a time. `rootwelld` runs only on Linux: elsewhere
`init`, `serve` and the offline commands refuse and make nothing.

Account passwords unlock no data; they only sign in (C108). The running
service holds the instance key, so a compromised live host reveals the keys.
Swapping in a whole older `rootwell.db` is not detected (RW-13). Losing both
the key file and the recovery code loses every saved certificate and key.
A backup is a sealed copy of the whole vault, without the instance key;
`rootwelld restore` puts one back, `key-rotate` moves the vault to a new
instance key, and `key-export` prints the key's recovery code again (C114).

Guarded by `TestRecordsRoundTripWithRevisionsAndGenerations`,
`TestAFailedUpdateKeepsNothing`, `TestAnotherKeyCannotOpenTheVault`,
`TestCreateNeverReplacesAndOpenNeverCreates`,
`TestASealedRecordMovedOrChangedIsRefused`,
`TestAChangedRevisionOrByteIsRefused`, `TestNoPlaintextOrNameReachesTheDisk`,
`TestIndexesDifferBetweenVaultsAndKinds`, `TestMalformedInputsAreRefused`,
`TestRecoveryCodeRoundTripsAndRefusesDamage`,
`TestTheCheckedVaultNeedsAPrivateDirectory`,
`TestTheKeyFileIsPrivateAndNeverReplaced`, `FuzzOpenSealedRecord`,
`TestSaveListsTheCertificateAndRefusesAStalePageOrADuplicate`,
`TestWritesOutsideTheListLeaveAnOpenPageCurrent`,
`TestAKeyIsSavedApartAndOnlyALoanOpensIt`,
`TestARecordMovedToAnotherCertificateIsRefused`,
`TestTheListStopsAtItsLimit`, `TestStoredRecordsHoldNoUnknownFields`,
`TestContainerVolumeDrill`,
`TestLinuxCertificatesNeedAReadySessionAndThePageHeader`,
`TestLinuxCertificatesLiveInTheVaultAndSurviveARestart`,
`TestLinuxInitNeedsSAVEDAndLeavesAWorkingSetupCode`,
`TestNonLinuxInitCreatesNothing`, `TestNonLinuxOfflineCeremonyFailsClosed`,
and `TestKeyRestoreRebuildsTheKeyFileAndNeverReplacesOne`.

## C106 — PFX import cannot bypass public/key custody boundaries (ADR 0087)

The bounded PFX decoder (the profile of C57, widened by ADR 0089) runs in a
dedicated one-shot browser worker; the server accepts only the existing
certificate/encrypted-key contract. A PFX without a password opens with an
empty one. A refusal the engine names (wrong password, unsupported
protection, no integrity check) leaves the worker as a short code only, so
the page never blames the password for a format it does not read.
Raw PFX byte copies, passwords, plaintext keys and private metadata never enter
pending preview or public output; file references/digests bind the source.
All related certificates are retained, included roots
are not trusted, and both worker and server recompute matching identity.
Temporary encryption uses the existing reviewed exporter and crypto/rand;
source/file digest, not randomized ciphertext, binds Check/Save. Ready-first
transfer, no network/storage, scoped deadlines, strict output, cancellation and
owned-buffer clearing protect the browser boundary; invalid/stale/late work
cannot publish or start a Save. What is saved goes into the vault like any
other Save (C68, C107).

Guarded by `TestPreparePreservesPublicCollectionAndOnlyEncryptsMatchingKey`,
`TestPrepareRefusesWrongPasswordTamperAndUnrelatedWithoutPartialMaterial`,
`TestPrepareOpensLegacyWindowsAndPasswordlessPFX`,
`FuzzPFXImportNoPartialSecret`, `TestPFXImportPreparationHasNoNetworkOrCustodyAuthority`,
`TestCertificatesPageAndItsScriptsRemainBehindReadyAccess`,
`TestLinuxCertificatesLiveInTheVaultAndSurviveARestart`,
`TestCertificateSavePublicationNeedsCurrentSessionAndCancellation`,
`scripts/test-certificates.mjs` and `scripts/test-certificate-pfx-worker.mjs`.

## C105 — Saved navigation cannot grant a website connection (ADR 0086)

Retired on 22 November 2026 with the page rebuild: the handoff of a saved
certificate from Certificates into Website check is gone. Certificates now only
links to Website check with the name after `#`, which fills in the name
(`scripts/test-website-check.mjs`); the check itself stays under C103.

## C104 — Expected files cannot repair or replace a live chain verdict (ADR 0085)

Retired on 22 November 2026 with the page rebuild: Website check no longer
compares expected files. The API still accepts only a target and confirmation,
never certificates, fingerprints, keys or trust
(`TestWebsiteComparisonCannotUploadCertificatesOrTrustToAPI`), and issuer
checks still locate a broken signature at its exact depth
(`TestIssuerChecksLocateExactBrokenSignatureAtEachDepth`).

## C103 — Website diagnosis has explicit bounded network authority (ADR 0084)

Website observation is a separate explicit ready-session capability, not a
network path from the file pages (Inspect, Convert, Request) or the offline
`rootwell` Workbench. A target is a DNS name or IP address with an optional
port; paths, credentials and queries are refused. All bounded DNS answers must
be allowed: public or private, never loopback, link-local, metadata, reserved
or IPv4-embedding transition addresses (ADR 0090). At most three connections
go to validated numeric addresses, and the name remains SNI. One global
in-flight observation, a 5-second interval, deadlines and socket byte bounds
apply. No application
data, credentials, proxy, redirects or certificate-URL retrieval is sent.
Native non-Linux production calls refuse before network work. Peer roots do
not become trusted; only self-signed authorities the owner saved in
Certificates may end a path, and a check saves nothing. Issuer names alone
cannot create a signature link. Every finding names the certificates it is
about; failures name only the canonical target and the dialed address. Path,
hostname and current dates remain separate facts. No result is published
after the original session is lost; nothing is persisted. The page has no
sample websites; each press of Check sends one request with the fixed
confirmation the API requires, and an empty entry sends nothing.

Guarded by `TestTrustedPathDoesNotNeedServerSentRoot`,
`TestSameIssuerNameCannotForgeSignatureLinkOrTrust`,
`TestMissingIssuerAndPeerRootCannotCreateTrust`,
`TestNameAndDatesAreSeparateFromPathLinks`,
`TestPresentationOrderDoesNotDeterminePath`,
`TestCrossSignedIssuerAmbiguityIsNotMissingOrWrongSignature`,
`TestMalformedAndBoundedInput`, `TestTargetIsAnOriginNotAFetchURL`,
`TestOwnMachineLinkLocalAndReservedAddressesAreRefused`,
`TestFailuresSayWhatHappened`, `TestClassicRetryWhenTheGreetingIsDropped`,
`TestIncompleteHandshakeStillShowsCertificatesAndRepeatsAreNamed`,
`TestSavedRootTrustsAPrivateChainAndNothingElse`,
`TestOlderChainAndSentRootAreNotProblems`,
`TestMissingIntermediateNamesTheIssuer`,
`TestWebsiteCheckTrustsOnlyRootsSavedInCertificates`,
`TestWebsiteFailuresAreExplainedWithoutPeerText`,
`TestRealSyntheticTLSIsPinnedSNIOnlyAndSeparatelyVerified`,
`TestRefusalsHaveNoDialOrPartialReport`, `TestWebsiteConsentExactAndNoSecrets`,
`TestCancellationAndRevocationAfterDialCloseWithoutHandshake`,
`TestHandshakeCancellationAndPostHandshakeRevocationPublishNothing`,
`TestBoundedConnectionStopsUnboundedPeerInputAndWrites`,
`TestWebsiteGateNeedsReadyOriginConsentAndThrottleAndWritesNothing`,
`TestWebsiteCodeStageAndLateSessionCannotPublish`, `FuzzAnalyzePublicChain`,
`FuzzTarget`, `FuzzWebsiteConsent` and `scripts/test-website-check.mjs`.

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

Page assets are self-hosted and contain no third-party subresources, inline
script or inline event handler. Every page, signed in or not, is served under
one strict policy: scripts, styles, images, fonts and connections only from
this server, WebAssembly compilation allowed, nothing inline and no framing.
The WebAssembly loader fetches only the engine and has no DOM or selected-file
access. The scripts that read chosen files (Inspect, Convert, Request and the
shared `ui.js`) have no network, storage, worker, dynamic-code or HTML-writing
capability. Certificates talks only to its own API and writes no HTML or
browser storage. The private-key, PFX and CSR/key-match worker paths are
bounded, cancellable and clear their bytes.

Guarded by `TestPagesAreSelfContained`,
`TestEveryPageIsServedUnderTheStrictContentSecurityPolicy`,
`TestPagesSeparateFileAndNetworkCapabilities`,
`TestInspectFileHintMatchesItsLimit`, and `TestPageElementReferencesResolve`.
Every page wears the one shared sheet and no inline style
(`TestEveryPageWearsTheSharedSheetAndNoInlineStyle`). Text contrast in both
themes, for every colour text is set in, is guarded by
`TestEveryColourTextIsSetInIsLegible`; legible controls by
`TestRootwellIsGraphiteAndItsControlsAreLegible`; a control colour never
doubling as a verdict colour by `TestTheToolColourIsNeverAVerdictColour`; the
one pinned typeface by `TestTheTypefaceIsTheOneChosenAndCarriesItsLicence`; and
the shared rail on every page by `TestEveryWorkspacePageCarriesTheSharedShell`.
Sign out reads no file and talks only to `/api/session`
(`scripts/test-session.mjs`).

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
`TestFailureResponseFailsClosedForUnknownCode`, `FuzzProcessReturnsJSON`, and
`scripts/test-browser-wasm.mjs`.

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

Inspect accepts up to eight chosen files, at most 16 MiB together, each a
public DER certificate or a strict PEM collection read through the same Go
parser as CLI `explore`. The engine's chain analysis then bounds the whole
selection to eight files, 16 MiB and 64 certificates and refuses a certificate
repeated across files. Secret-bearing, mixed, malformed, duplicate, excessive,
and trailing input shows no partial result and no reflected certificate text
or raw bytes; a private key, PFX or CSR is refused with a fixed message naming
the page that takes it. The response is versioned, bounded, and contains public
metadata only. Its explicit status is `not-performed` with trust anchor
`not-selected`; the page uses text nodes and never turns a CA flag into trust.
The file-reading scripts have no network or storage capability, and the page
forgets the certificate and any typed key password when it is hidden or left.

Guarded by `TestProcessPublicCertificateAndBundle`,
`TestProcessRejectsUnsafeInputWithoutEchoOrPartialOutput`,
`TestProcessEnforcesCertificateCountWithoutPartialResult`,
`TestFailureResponseFailsClosed`, `FuzzProcessPublicBundleReturnsJSON`,
`TestProcessRejectsUnsafeCollectionsWithoutEcho`,
`TestPagesSeparateFileAndNetworkCapabilities`,
`TestInspectFileHintMatchesItsLimit`, `scripts/test-browser-wasm.mjs`, and
`scripts/test-inspect.mjs` for a chain spread over files, the refusal of more
than eight files and of PFX, key and CSR files, and forgetting on leaving.

## C21 — Browser export contains only the explicitly chosen public certificate

The engine's export re-parses one bounded public source and selects a
certificate by its full fingerprint, not bundle position, subject text, or
filename. It rejects changed, secret-bearing, malformed, duplicate, excessive,
and unmatched input without partial output. PEM and DER output are re-parsed
and must match the selected DER bytes and fingerprint. A private key or PFX is
never accepted by this export. Convert builds its certificate files from these
exports, one certificate at a time in chain order: PEM (`.pem`, the full chain
without the root), Certificate only (`.crt`, PEM) and DER (`.cer`). Downloads
are browser-managed; the page does not write directly to the filesystem or
send certificate bytes to an API. Browser/OS overwrite policy is outside this
guarantee.

Guarded by `TestPrepareExportsOnlySelectedCertificate`,
`TestPrepareRejectsChangedOrUnsafeSource`,
`FuzzPrepareNeverReturnsUnselectedCertificate`,
`TestPagesSeparateFileAndNetworkCapabilities`,
`scripts/test-browser-wasm.mjs`, and `scripts/test-convert.mjs`.

## C22 — Issuer candidates are signed relationships, never trust verdicts

The engine's chain analysis accepts only a bounded, strict public collection.
It checks raw issuer/subject name equality, CA constraints, and the certificate
signature before listing a possible issuer. Ambiguous parents remain separate
candidates; a self-signed CA is not a trust anchor. There is no hostname, time,
complete path, algorithm-policy, revocation, or private-key verdict. Signature
work is capped at 256 checks. Malformed, changed, duplicate, excessive, or
secret-bearing input hides the entire Inspect result. Inspect and Convert use
these links only to order and label the chain, drawn as text; Inspect calls a
chain complete when it ends at a self-signed certificate, which describes the
files, not trust. No network path is introduced.

Guarded by `TestProcessFindsSignedCandidatesWithoutTrust`,
`TestProcessRejectsUnsafeCollectionsWithoutEcho`,
`TestProcessBoundsSignatureWork`,
`FuzzProcessNeverReturnsTrust`,
`TestPagesSeparateFileAndNetworkCapabilities`,
`scripts/test-browser-wasm.mjs`, and `scripts/test-inspect.mjs`.

## C23 — Selected public bundle export cannot add or reorder certificates

Retired on 22 November 2026 with the page rebuild: no page offers the old
Explore selection export. The engine's bundle export still refuses changed,
unsafe and unselected input (`TestPrepareExportsExplicitOrderedSubset`,
`TestPrepareRejectsChangedUnsafeAndUnselectedInput`,
`FuzzPrepareBundleNeverExportsUnselectedCertificate`,
`scripts/test-browser-wasm.mjs`).

## C24 — Browser Verify uses only explicit trust and the CLI policy

Retired on 22 November 2026 with the page rebuild: the browser Verify panel is
gone. The engine's verifier still uses only an explicit trust file and the CLI
policy (`TestSimpleAndExplicitUseSameTrustVerdict`,
`TestSimpleNeverTrustsSourceRoot`, `TestSimpleRejectsAmbiguousAndSecretSources`,
`TestExplicitClassifiesRefusalsWithoutPartialChain`,
`FuzzSimpleNeverUsesSourceAsTrust`, `scripts/test-browser-wasm.mjs`).

## C25 — Verified fullchain export re-verifies and excludes the root

Retired on 22 November 2026 with the page rebuild: no page offers the verified
fullchain download. The engine's export still re-verifies the same path and
leaves the root out
(`TestPrepareVerifiedFullchainExcludesRootAndPreservesVerifiedOrder`,
`TestPrepareRefusesUnverifiedChangedAndUnsafeInputs`,
`TestPrepareExplicitNeedsSameVerifiedPath`,
`FuzzPrepareNeverExportsUnverifiedSource`, `scripts/test-browser-wasm.mjs`).

## C26 — Optional root pin binds the offline verdict to a full fingerprint

Retired on 22 November 2026 with the page rebuild, together with the browser
Verify panel. The engine still compares a pin only with the final anchor of
the verified path (`TestRootPinMatchesOnlyCompleteVerifiedPathAnchor`,
`scripts/test-browser-wasm.mjs`).

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

Retired on 22 November 2026 with the page rebuild: the Explore expiry overview
is gone. Inspect shows days left for each certificate from the engine's UTC
validity dates (`TestProcessPublicCertificateAndBundle`,
`scripts/test-inspect.mjs`); that is not a trust, renewal or deployment verdict.

## C29 — Guided handoff cannot choose trust or conceal changed sources

Retired on 22 November 2026 with the page rebuild: the guided handoff from
Explore to Verify is gone with both panels. Nothing replaces it.

## C30 — Possible signing links never become a trust path

Retired on 22 November 2026 with the page rebuild: the Explore link guide is
gone. The issuer links Inspect draws remain under C22.

## C31 — Public report is explicit, bounded, and snapshot-bound

Retired on 22 November 2026 with the page rebuild: the public JSON report
download is gone. Nothing replaces it.

## C32 — Initial installation password cannot open stored data

Retired on 24 November 2026 with the access file (ADR 0088): there is no
generated setup password any more. `rootwelld init` prints a one-time setup
code, and an account exists only once its phone is confirmed (C108).

## C33 — The gate serves pages only to a signed-in session

Only the sign-in and setup pages, their scripts, the stylesheet, the
colour-scheme script, the icon, the typeface and the authority's certificate
(`/rootwell-ca.pem`) are served before sign-in. Every other page, script,
worker and API needs a signed-in session; a session still at the setup or
phone-code step is sent to sign in (C109). The server listens on both loopback
addresses, and on a LAN or VPN address only when `--listen` names one (C112).
It refuses a request without TLS, an unexpected Host, a cross-origin or
headerless change, a query string, a malformed or oversized body, and unknown
JSON fields. Forms never fall back to sending a password in a URL. It refuses
to start when a page file or the engine is missing.

Guarded by `TestGateRejectsCrossOriginHostAndMalformedRequests`,
`TestOnlyHTTPSToTheConfiguredNamesIsServed`,
`TestAuthFormsCannotFallBackToPasswordInGetURL`,
`TestGatewayRefusesIncompleteBrowserAssets`,
`TestCertificatesPageAndItsScriptsRemainBehindReadyAccess`,
`TestSetupSavesTheAccountOnlyOnceThePhoneIsConfirmed`,
`TestSignInTakesThePasswordThenACode`,
`TestListenLoopbackHoldsBothAddresses`, and
`scripts/test-rootwelld-auth.mjs`.

## C34 — Sessions cannot silently survive an observed access-file change

Retired on 24 November 2026 with the access file (ADR 0088): accounts live in
the vault, which one process holds at a time, so nothing changes them behind
the running service. A change of password, phone or recovery codes ends the
account's other sessions itself (C109).

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

Retired on 23 November 2026 with the old encrypted inventory image
(ADR 0088): the standalone `inventoryseal` codec is gone. The vault seals
every record under its own key, bound to its kind, ID and revision (C107);
`FuzzOpenSealedRecord` now fuzzes the vault's sealed records.

## C37 — New installation identity is authenticated and stable

Retired on 24 November 2026 with the access file (ADR 0088): the access
envelope and its installation ID are gone with `internal/instanceaccess`.
The vault binds every record to itself (C107).

## C38 — Offline recovery codec does not silently enroll credentials

Retired on 24 November 2026 with the access file (ADR 0088): the password
recovery wrap is gone. An account's recovery codes are kept as keyed digests
in its vault record (C108).

## C39 — Legacy identity preparation does not mutate access

Retired on 24 November 2026 with the access file (ADR 0088): there are no
access files to upgrade.

## C40 — Linux access changes serialize cooperating writers

Retired on 24 November 2026 with the access file (ADR 0088): account changes
are vault transactions, and one process holds the vault at a time (C107).

## C41 — Linux identity installation validates before replacing

Retired on 24 November 2026 with the access file (ADR 0088): there are no
access files to install.

## C42 — Linux offline recovery keeps the same data key and rotates authority

Retired on 24 November 2026 with the access file (ADR 0088):
`recovery-enroll`, `recovery-rotate` and `recovery-reset` are gone. A lost
phone is replaced with a recovery code on the Account page; a lost password,
or a lost phone together with the recovery codes, with
`rootwelld setup-code` and the account's name (C108).

## C43 — Access snapshots prove both recovery paths and never overwrite

Retired on 24 November 2026 with the access file (ADR 0088):
`access-snapshot`, `access-verify` and `access-restore` are gone. A backup
now comes from the Installation page, and `rootwelld restore` puts it back
(C114, `docs/RECOVERY.md`).

## C44 — Offline Linux ceremonies never take secrets from argv or a live daemon

`rootwelld init`, `setup-code`, `key-restore`, `key-export`, `key-rotate` and
`restore` need an interactive local terminal for both input and output;
without one they read and print nothing. `key-restore`, and `restore` when
the key file is missing, read the instance key's recovery code without echo,
never from argv, the environment, a pipe or a file; `key-export` and
`key-rotate` print a recovery code there (C114). Their argv holds only paths
and, for `setup-code`, an account name, which is not secret. While
`rootwelld serve` holds the vault, `setup-code`, `key-restore`, `key-export`
and `key-rotate` cannot open it and change nothing. A setup code is printed
to the terminal only after it is saved, and a failed display does not put
the code in the error. Off Linux they refuse and make nothing. This is not
protection against a compromised terminal, its scrollback, or a malicious
process of the same user.

`serving-names` reads and prints no secret, only the new authority's public
fingerprint, so it runs without a terminal too, as from a script. While
`rootwelld serve` holds the vault it cannot open it either, and changes
nothing (C112).

Guarded by `TestOfflineCommandClassificationAndNoSecretArgv`,
`TestSetupCodeDisplayFailureDoesNotReturnTheCode`,
`TestLinuxInitNeedsSAVEDAndLeavesAWorkingSetupCode`,
`TestLinuxSetupCodeMakesTheFirstAccountOrReplacesItsSignIn`,
`TestKeyRestoreRebuildsTheKeyFileAndNeverReplacesOne`,
`TestLinuxServingNamesMakeANewAuthorityForThoseNames`,
`TestLinuxKeyExportPrintsTheCodeOfTheKeyThatOpensTheVault`,
`TestLinuxKeyRotationNeedsSAVEDAndLeavesOnlyTheNewKey`,
`TestLinuxRestoreWritesABackupOnlyIntoAnEmptyDirectoryAndOnlyIfItOpens`,
`TestNonLinuxInitCreatesNothing`, and
`TestNonLinuxOfflineCeremonyFailsClosed`.

## C45 — Complete inventory images authenticate context before releasing records

Retired on 23 November 2026 with the old encrypted inventory image (ADR 0088):
there is no complete image any more. Each certificate is a vault record,
checked when it is read (C107).

## C46 — Linux inventory activation and full snapshots preserve recoverability

Retired on 23 November 2026 with the old encrypted inventory image
(ADR 0088): durable activation, full snapshots and their offline commands
are gone. `rootwelld init` now creates the vault (C107). A backup is a
sealed copy of the whole vault, made while the service runs (C114).

## C47 — Public inventory upload is explicit, authenticated, and non-verifying

Inspect, Convert and Request upload nothing. Certificates reach the
daemon only through the certificate API, which the Certificates page calls when
the person adds one; the inventory list only reads. Every route needs a
signed-in session; a session still at the setup or phone-code step is
refused. POST also requires exact same-origin
and the custom header, rejects duplicate or unknown JSON fields and oversized
bodies, and runs the strict public parser again before the vault write. GET
requires the custom header and refuses cross-site fetch metadata.
Responses omit DER and private bytes, claim no verification, and carry the
list's change count and the server-clock save time. No automatic backup, trust,
deployment, revocation or notification follows. The running service holds the
instance key; a compromised process is outside this boundary.

Guarded by `TestLinuxCertificatesNeedAReadySessionAndThePageHeader`,
`TestLinuxCertificatesLiveInTheVaultAndSurviveARestart`,
`TestCertificateEndpointsNeedASignedInSession`,
`TestCertificateRequestModesRejectMalformedAndAmbiguousJSON`,
`TestCertificateRequestBoundsAndDownloadMode`,
`TestInventoryOutputNeverSerializesCertificateBytes`,
`TestPagesAreSelfContained`, `TestPagesSeparateFileAndNetworkCapabilities`,
and `scripts/test-certificates.mjs`.

## C48 — Linux container volumes keep recovery separate and reject unsafe reuse

The development Compose service runs the daemon on the Linux host's network:
on loopback, and on a LAN address only when a `compose.override.yaml` adds
`--listen` (C112). It mounts two private directories: the data directory at
`/data`, and a separate key directory at `/key`, read-only, that holds the
instance key file (C107). Offline maintenance runs `init`, `setup-code`,
`key-restore`, `serving-names`, `key-export`, `key-rotate` and `restore`. It
has no network, and mounts `/key` read-write, for those that write the key
file (`init`, `key-restore`, `key-rotate`, and `restore` without one), and the
backup directory at `/backup`, which `restore` reads from (C114).
No password, setup code, recovery code or key is
configured through argv or environment. The maintenance service explicitly
disables Docker logging with driver `none` and no options; TTY alone does not
prevent retention of interactive secrets. The real-container drill verifies
the effective driver and that harmless attached usage output is not available
through `docker logs` (ADR 0052). Serving retains secret-free diagnostics.
Custom configs, terminal recording, host administrators and previously
retained logs remain outside this boundary.

A disposable CI drill seeds a volume (with the base commit's drill when the
base already has the vault, otherwise with the candidate), then reopens it in
a new container with the candidate and refuses another key. It serves the
volume, fetches `/rootwell-ca.pem` and checks that the sign-in page verifies
against it over TLS 1.3, checks that the server mounts only `/data` and
`/key`, proves that a second opener is refused while the server holds the
vault and that a data directory others can read is refused, and restarts. A seed made by this
release's drill also writes a setup code beside the volume, and the drill
checks that the server's log never holds it. The drill does not restore a
backup; `rootwelld restore` has its own tests (C114). It does not establish
offsite durability, automatic backup, external anti-rollback, Windows support,
or production readiness.

Guarded by `TestContainerVolumeDrill`,
`scripts/test-container-config.mjs` (overprivileged and ephemeral-volume
sabotage, and a writable key mount on the server), and
`scripts/test-container-volume.sh` in the required Linux container CI job.

## C49 — One public certificate can have bounded manual locations, never a deployment verdict

The fingerprint remains unique; a second copy is refused. An explicit
same-origin, session-bound POST can add one of at most 32 plain-text, nonempty,
exact place labels to a saved certificate. It names the generation the page
last read; any other gets 409 and writes nothing. Only that certificate's
vault record is resealed, as its next revision; its certificates, its key and
the time it was added do not change. Stale generation, missing certificate,
duplicate, malformed or excessive labels, a damaged record, and cross-origin
or anonymous requests do not write. Places are notes a person types, not
verified deployments.

Guarded by `TestAssociateLocationIsBoundedExplicitAndDetached`,
`TestPlacesAndOwnerChangeOneAtATime`,
`TestLinuxCertificatesLiveInTheVaultAndSurviveARestart`,
`TestLocationInputRejectsMalformedAndDuplicateFields`,
`TestInventoryOutputNeverSerializesCertificateBytes`, and
`scripts/test-certificates.mjs`.

## C50 — Owner correction is explicit, generation-bound, and non-verifying

An authenticated same-origin POST can replace one saved certificate's owner
note or explicitly clear it to unknown. It names the generation the page last
read; any other gets 409. Malformed or non-string owner, no-op, missing
fingerprint, stale page, unauthorized session and cross-origin requests do not
write. A correction reseals only that certificate's vault record; its
certificates, places, key and the time it was added do not change. API output
omits DER and makes no verified ownership claim. There is no edit history.

Guarded by `TestUpdateOwnerChangesOnlyDetachedManualNote`,
`TestPlacesAndOwnerChangeOneAtATime`,
`TestLinuxCertificatesLiveInTheVaultAndSurviveARestart`,
`TestOwnerInputRequiresExplicitBoundedStringAndGeneration`,
`TestContainerVolumeDrill` (a reopened volume takes an owner change), and
`scripts/test-certificates.mjs`.

## C51 — Manual location correction cannot become deployment or certificate deletion

An authenticated same-origin POST can rename one exact place to a valid,
unused label or remove one exact label. It names the generation the page last
read; stale, malformed, unknown, duplicate, no-op, cross-origin and
unauthorized requests do not write. Only that certificate's vault record is
resealed; its certificates, fingerprint, owner, key, the time it was added and
other certificates do not change. Removing the first label promotes the next;
removing the last leaves an unknown place and does not delete the certificate
or touch a server. On the Certificates page a place is removed from its chip,
which changes only that note.

Guarded by `TestRenameAndRemoveLocationPreserveCertificateAndUnknownState`,
`TestPlacesAndOwnerChangeOneAtATime`,
`TestLinuxCertificatesLiveInTheVaultAndSurviveARestart`,
`TestLocationChangeInputRequiresExactActionAndFields`, and
`scripts/test-certificates.mjs`.

## C52 — Expiry triage is a local view, not a trust verdict

The Certificates page counts saved certificates as good, expiring soon (30
days or less) or expired against the browser clock, sorts them by end date,
and filters or searches them in the page only. Counts cover every record even
when a filter is pressed. Filters and search terms are not sent or stored and
change nothing saved. Server-clock expiry stays with the API (ADR 0041, C64).
The counts are not a deployment, trust or renewal verdict; an incorrect browser
clock remains a residual risk, and nothing is sent as a reminder.

Guarded by `scripts/test-certificates.mjs`.

## C53 — Inventory UI does not export sensitive metadata

The Certificates page has no bulk selection and no bulk export. Its only
downloads are one saved certificate, its full chain, the certificate with its
key, or the key alone, through the certificate API under C68's password rules.
A backup comes from the Installation page, not this one, after a fresh code:
the whole vault, sealed, which opens only with the instance key and never
holds it (C114). The development visual demo was
retired on 22 November 2026 with the page rebuild.

Guarded by `scripts/test-certificates.mjs`.

## C54 — Record deletion is exact, explicit, and never a revocation claim

One saved certificate, its notes and its key can be removed only by an
authenticated ready same-origin POST with the displayed generation, a
duplicated exact fingerprint, and a fixed confirmation phrase. The
Certificates page asks first in a dialog that says servers are not changed,
then sends the exact fingerprint twice with the fixed phrase. A certificate
with a saved key is deleted only within ten minutes of a phone code; without
one the server answers 428 and writes nothing, and the page asks for a code
(C111). The certificate
record and its key record go in one vault transaction; other certificates keep
their records. Stale, absent, malformed, anonymous, cross-origin and headerless
attempts do not write. This does not securely erase old bytes from the
database file, delete copies of the data directory, revoke a certificate, or
change a server; an earlier copy still holds the certificate. No automatic
deletion occurs.

Guarded by `TestDeleteTakesTheKeyWithIt`,
`TestLinuxCertificatesLiveInTheVaultAndSurviveARestart`,
`TestLinuxACertificateWithoutAKeyIsDeletedWithoutAFreshCode`,
`TestInventoryDeleteInputRequiresTypedFingerprintConfirmationAndGeneration`,
and `scripts/test-certificates.mjs`.

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

The offline CLI and every browser PFX path accept at most 1 MiB of the PFX
profile of ADR 0089: a MAC with SHA-1, SHA-256 or SHA-512; legacy PKCS#12
3DES or RC2, or PBES2/PBKDF2 with AES-128/192/256-CBC and an HMAC-SHA-1,
SHA-256 or SHA-512 PRF; exactly two safes in either order, the one shrouded
key in an unencrypted safe, and only certificate and shrouded-key bags
there. Every visible KDF work factor (at most 250,000 iterations), salt, IV,
key length, ciphertext length and bag and attribute count is checked before
password-based decoding. A PFX without a MAC, a SHA-384 or SHA-224 MAC or
PRF, PBMAC1, one or three safes, two encrypted safes, plain key, CRL, secret
or nested bags, and anything malformed are refused before a password is
tried. The CLI uses a 10-second one-shot deadline and a local interactive
password, which may be empty for a PFX saved without one. After the MAC
verifies, the pinned decoder's strict lister enumerates every bag, so an
unknown bag inside an encrypted safe is refused; only when that lister stops
at a bag attribute it cannot name (Windows machine-key and extended-property
labels) does the attribute-free decoder read the same authenticated contents,
still refusing a second key. It never assumes the first certificate is the
leaf, requires exactly one RSA or EC key and one matching non-CA
certificate, rejects duplicate or ambiguous material, and returns only public
metadata. Additional certificates remain untrusted and unordered. A wrong
password is named as wrong and never confused with an unsupported format;
tampering, malformed/trailing input, unsupported profile, excessive KDF cost,
and non-TTY input produce no partial public result or secret echo. It never
exports or persists a key, and does not prove hostname, trust, revocation, or
a live deployment. Runtime memory erasure is best effort, not guaranteed. An
unbounded KDF hidden in an encrypted safe is not detected before decode; the
CLI deadline limits the operator-facing wait, but this decoder must not be
reused in a long-lived process. With Windows attributes, a CRL, secret or
nested bag inside an encrypted safe would be skipped, not stored.

Guarded by `TestInspectModernPFXPublicOnly`,
`TestInspectRejectsWrongPasswordTamperAndUnsupported`,
`TestPreflightRejectsExcessiveKDFBeforeDecode`,
`TestInspectRejectsMismatchedKeyAndDuplicateCertificate`,
`TestInspectShowsAdditionalCertificateWithoutTrustClaim`,
`TestInspectOpensProducerProfiles`, `TestInspectOpensEmptyPasswordBothWays`,
`TestInspectWindowsAttributesStillOpen`,
`TestInspectRefusesUnknownBagInEncryptedSafe`,
`TestPreflightRefusesUnsupportedLayoutsBeforePassword`,
`TestOpenLendsOnlyTheMatchingKeyAndRefusesNoCallback`,
`TestCodeNamesEachRefusal`, `TestBuilderAgreesWithPinnedDecoder`,
`TestPFXFixtureBuilderIsTestOnly`,
`TestInspectModernOpenSSLGeneratedPFX`,
`FuzzPFXPreflight`, `TestPFXInspectShowsOnlyPublicSummary`, and
`TestPFXInspectRefusesNonTTYAndWrongPasswordWithoutPartialOutput`, and
`TestPFXInspectRejectsUnsupportedBeforePasswordPrompt`, and
`TestPFXInspectDeadlineReturnsWithoutPartialResult`, and
`TestPFXInspectDecoderPanicIsNotPrinted`.

## C58 — PFX public extraction is exact-selection and never key export

The offline CLI accepts only a complete canonical SHA-256 fingerprint printed
by inspection, authenticates and validates the same bounded PFX profile (C57),
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
non-CA certificate fingerprint from an authenticated PFX of the bounded
profile of C57. The key comes from the same decode that matched it to that
certificate, whatever the bag order in the file.
The output is one password-encrypted PKCS#8 PEM block, never plaintext,
stdout, JSON, inventory, or browser content. A new terminal-entered output
password is confirmed, meets policy, and differs from the PFX password.
Unsupported OS, non-TTY, malformed/oversized/unsupported/tampered input, wrong
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

Convert takes one private key alone, at most 64 KiB: a strict unencrypted
PKCS#8, RSA PKCS#1, or EC SEC1 PEM/DER key, or a bounded modern encrypted
PKCS#8 PEM/DER key. Since ADR 0089 the engine's key entry points first read
the key as C115 does: a byte order mark, text around the block or an
`EC PARAMETERS` block for the key's own curve may come with it, and an old
OpenSSL `Proc-Type` encrypted key is opened with its password (never
written in that form). Inspection returns public metadata only. An encrypted key
needs its current password before any format is offered, and again on export;
a wrong password publishes nothing and is named as wrong. Export binds the full displayed public
fingerprint. The PEM choice is encrypted PKCS#8 when the person types or
generates a new 20–128 character password, which must differ from the key's
current password; left empty, it is unprotected PKCS#8. The DER and older PEM
choices are unprotected. A generated password reaches the clipboard only when
the person presses Copy. Malformed, changed, oversized, wrong-fingerprint, wrong-password,
unsupported target/profile, and PFX input to the key reader publish no key.
The page script cannot upload or persist selected bytes; buffers and password
fields are cleared best-effort, and everything is forgotten after ten idle
minutes or on leaving the page. Inspect's certificate reader stays public-only.
The browser and OS may retain memory/download copies and control file
permissions; no vault or per-user key authorization is claimed.

Guarded by `TestInspectAndExportEncryptedPrivateKeyFormats`,
`TestPrivateConversionRefusesMalformedChangedAndWeakPassword`,
`FuzzInspectPrivateKeyNoSecretEcho`,
`TestKeyPreparesKeyFilesForTheStrictReaders`,
`TestEncryptedInputAndPlaintextTargets`,
`TestEncryptedInputRefusesUnsafeProfilesAndNoPartialExport`,
`TestPagesSeparateFileAndNetworkCapabilities`,
`TestEveryPageIsServedUnderTheStrictContentSecurityPolicy`, and
`TestPagesAndScriptsNeedASignInAndWorkersReachNoNetwork`, plus
`scripts/test-browser-wasm.mjs`, `scripts/test-convert.mjs` and
`scripts/test-workbench-private-worker.mjs`.

## C61 — Browser PFX stays isolated, bounded, and honest

Convert opens one PFX on its own, recognised by its content, at most 1 MiB,
with the authenticated profile and pre-decryption KDF caps of C57, and its
password, which may be empty for a PFX saved without one. A refusal says
whether the password was wrong or the protection is not one Rootwell reads.
Inspection returns
public certificate metadata only; additional certificates are included, not
trusted. Every output reauthenticates the held PFX bytes with its password in
the worker. Certificate outputs bind their full fingerprints. The private key
comes out as unprotected PKCS#8 PEM, or as newly encrypted PKCS#8 PEM under a
new password that must differ from the PFX password. A new PFX always needs a
new 20–128 character password, different from the current one. It is
AES-256 with 100,000 iterations by default; the labelled choice for older
Windows writes 3DES under a SHA-1 MAC with 2048 iterations, and every new PFX
must open in the same reader before it is offered. Creation
accepts one strict matching RSA/ECDSA key (unencrypted or bounded encrypted
PKCS#8), a non-CA certificate, and optional ordered issuers; a key that belongs
to another certificate is refused. Wrong passwords, tampering, changed
selection, mismatch, unsupported profiles, malformed inputs, stale operations,
and worker timeout request no download. Neither path writes the Certificates
store or any vault.

The one-shot PFX worker receives bounded transferred buffers only after
readiness. The authenticated gateway denies worker network connections and
child workers, and the file-reading script has no network/storage/markup-
injection capability. Best-effort buffer clearing and browser download
restrictions do not promise memory erasure, private filesystem permissions, no
overwrite, or protection from a malicious extension or compromised host. A
release still requires independent security audit.

Guarded by `TestCreateInspectExtractAndRefuse`,
`TestCreatePFXFromEncryptedKey`, `TestEncryptedPFXCreationRefusesUnsafeInputs`,
`TestPFXRevealReauthenticatesAndMatches`,
`TestPFXOutputsOpenWindowsAndPasswordlessPFX`,
`TestCreateOlderWindowsProfileReadsBack`,
`TestCreateOlderWindowsProfileIs3DESAndReadable`,
`TestPagesSeparateFileAndNetworkCapabilities`,
`TestEveryPageIsServedUnderTheStrictContentSecurityPolicy`, and
`TestPagesAndScriptsNeedASignInAndWorkersReachNoNetwork`, plus
`scripts/test-browser-pfx.mjs`, `scripts/test-workbench-pfx-worker.mjs` and
`scripts/test-convert.mjs`.

## C62 — Private-key display is explicit, transient and separate

Retired on 22 November 2026 with the page rebuild: no page shows a private key
on screen, so the 30-second view is gone. The PFX worker's reveal step, which
now produces Convert's unprotected key download (C61), still reauthenticates
and binds the inspected identity (`TestPFXRevealReauthenticatesAndMatches`,
`TestPFXRevealRefusesUnsafeInputs`).

## C63 — Offline key + CSR work is bounded and never issuance or trust

Request makes a new RSA/ECDSA key with crypto/rand in a one-shot worker; the
key leaves the worker only encrypted as PKCS#8 under the person's new 20–128
character password, in a ZIP with the public signed CSR; the ZIP is not
encrypted. An existing supported key, opened with its password when it has
one, produces only a CSR. Every request is reparsed, signature-checked and
subject/SAN/public-key checked under the modern policy. The engine's CSR import
consumes one complete PEM/DER request at most 64 KiB; unknown attributes/
extensions, ignored email/URI names, duplicate/malformed names and weak
signatures fail closed. Its public export binds the full request fingerprint,
and returned-certificate comparison separately reports canonical public-key
identity, literal SAN differences, subject encoding/value changes and CA
status, with trust false; no page offers import, export or comparison since
22 November 2026. A fake certificate can copy a public key; issuer/chain/time/
purpose/revocation and deployment must not be inferred. One-shot worker
deadlines and page cancellation prevent stale downloads; the request and its
key are forgotten after ten idle minutes or on leaving the page. Secrets never
enter UI persistence, network, logs or public summaries; a generated password
reaches the clipboard only when the person presses Copy. Both directions
reject foreign/missing dedicated-worker event metadata before initialization
or secret transfer; this is not a Window message allowlist. Browser/OS copies
and actual download permissions remain outside the best-effort memory-clearing
claim.

Guarded by `TestGenerateEncryptedKeyAndSignedCSR`,
`TestExistingKeyCSRFormatsAndEncryptedInput`,
`TestCSRFromAllSupportedExistingKeyFamilies`,
`TestLargeDERCSRPublicExportPreservesSignedRequest`,
`TestReturnedCertificateComparisonDoesNotImplyTrust`,
`TestCSRRefusesMalformedUnsafeAndIgnoredFields`,
`TestCSRNameSubjectPasswordAndFormatRefusal`, `FuzzInspectCSR`,
`TestPagesSeparateFileAndNetworkCapabilities`,
`TestWorkbenchHasNoNetworkOrProcessImports`, plus
`scripts/test-browser-csr.mjs`, `scripts/test-request.mjs` and
`scripts/test-workbench-csr-worker.mjs`.

## C64 — Saved-certificate reminders bind one server instant and fail visibly

After the ready-session checks, a list read derives date-only expiry from one
UTC whole-second server instant. Reads do not change the vault generation or
any record. Exact NotAfter is expired; malformed or zero/reversed ranges are
invalid; long dates cannot saturate a duration. A server clock outside the
years 0 to 9999 releases no list. The API still omits certificate bytes and
claims no verification.

The old Certificates page's minute-spaced refresh, 120-second stale snapshot,
clock-disagreement warning and 7/14/30/90-day reminder windows were retired on
22 November 2026 with the page rebuild; the new page counts days left against
the browser clock (C52). There is no outbound notification, guaranteed
closed-page alert, discovery, trust, renewal or Porch change.

Guarded by `TestObserveExpiryExactBoundariesAndNoTrust`,
`TestObserveExpiryRejectsMalformedAndHandlesLongDates`,
`TestInventoryOutputUsesOneServerClockAndNeverMutates`, and
`TestLinuxCertificatesNeedAReadySessionAndThePageHeader`.

## C65 — Saved public handoff is exact, transient, and never implicit trust

Retired on 22 November 2026 with the page rebuild: the handoff of one saved
certificate from Certificates into the old Tools page is gone. Nothing
replaces it; saved certificates are downloaded through the certificate API
under C68.

## C102 — A local production account key cannot reuse staging identity or grant CA authority

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088):
the production account key record and its route are gone. Account keys
return with renewal in Phase 3c, as sealed vault records (C107).

## C101 — A production profile cannot promote staging identity or test trust

ADR0081 supplies two immutable fixed-environment descriptions and separate
offline production receipt trust. Zero/unknown profiles never choose a default
or endpoint. Account/order/resource identities cannot cross origins, account
bindings, aliases, credentials or unbounded/normalised paths. Existing runtime
validators explicitly select staging only. The catalog cannot connect, derive
keys, mutate state or grant authority.

Production receipt checking uses only embedded pinned ISRG X1/X2 and all exact
key/CSR/name/usage/expiry/bounded-chain constraints. Staging roots never enter
that pool; response-provided/changed/duplicate/substituted roots are refused.
Only successful checking produces non-test evidence; failures have no partial
result. No host trust or fetching. No production runtime route/consumer may be
added before separate authenticated environment custody and grant review.

Guards: `TestFixedACMEProfilesSeparateOriginsAccountsAndNamespaces`,
`TestFixedACMEProfilesUnknownAndMalformedNeverSelectDefault`,
`TestLegacyOrderValidationCannotSelectProduction`,
`TestProductionReceiptTrustIsFixedIndependentAndNeverIncludesStaging`,
`TestProductionReceiptUsesAllBindingConstraintsWithoutRuntimeRootOverride`,
`TestFixedACMEProfilesCannotBecomeRuntimePromotionOrTrustConfiguration`,
`FuzzFixedACMEProfileURLs`. These are layered synthetic/offline proofs, not a
real CA issuance, live DNS interoperability or independent release audit claim.

## C100 — A complete renewal borrows only its original ready session

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088):
the session renewal job is gone. Renewal returns in Phase 3c and needs
no session.

## C99 — Closed-request capacity cannot erase lineage or revive historical authority

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088):
closed staging requests and their archive pages are gone.

## C98 — Operator observations cannot revive terminal DNS mutation policy

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088):
DNS maintenance is gone.

## C97 — History capacity cannot erase evidence or reset operational authority

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088):
the history archives are gone. The vault keeps no activity history yet.

## C96 — Session timing watch cannot become signing, replay or unlock authority

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088):
the session timing watch is gone.

## C95 — Explicit timing cannot bypass an all-CA provider wait

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088):
the provider wait across every CA route is gone with those routes.

## C94 — Durable renewal timing cannot reroll or erase provider policy

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088):
the saved renewal timing is gone. The offline ARI policy and protocol stay
under C92 and C93.

## C93 — Staging ARI protocol cannot gain credentials or arbitrary endpoints

ADR0073 permits an internal two-GET fixed staging component only. Validate bounded
public non-replaced/current certificate before DNS; missing directory support
sends no certificate ID. Exact advertised resource, public DNS/numeric pin/TLS,
8s total, bounded headers/body/JSON, no proxy/redirect/retry/compression, one-use
budget and repeated permission/expiry checks. Fixed errors carry only bounded
wait hints, no raw body/URL/metadata. No signer/token/key, exported live function,
runtime consumer, saved state or UI authority before source-bound custody review.

Guards: `TestARIProtocolTwoPinnedPublicGETsNoCredentialsOrRedirects`,
`TestARIProtocolMissingAdvertisementDoesNotFetchCertificateID`,
`TestARIProtocolSourcePermissionAndExpiryRefuseBeforeDNS`,
`TestARIProtocolUntrustedResponsesCannotAddNetworkOrPartialInformation`,
`TestARIProtocolRevocationAndDeadlineCannotPublishLateResult`,
`TestARIProtocolOneUseURIAndRequestBudget`,
`TestARIProtocolUnsafeDNSAndPreSendRevocationCannotDiscloseID`,
`FuzzStagingARIURI`, `TestRenewalPolicyCannotAcquireRuntimeOrNetworkAuthority` and inherited pinned
transport/ARI parser/identifier/fuzz guards. Actual compiling two-way sabotage
is recorded in ADR0073; fake TLS is not live interoperability or production audit.

## C92 — Offline ARI policy cannot become renewal authority

ADR 0072: bounded UTF-8/unique-key/depth/budget JSON, strict RFC3339 instants and
positive window; one ARI Retry-After clamps read checks only, never DNS mutation
waits. Invalid/missing hints expose no trusted window; bounded error policy
never retries by itself. Standard X.509/ASN.1 preserves serial padding without
custom crypto. Random half-open-window selection is subject to current lifetime
and existing error backoff; stale/future/expired/invalid/entropy refusal returns
no partial selection. Local fallback uses actual lifetime and short-life policy,
not a fixed 90 days. No storage, signer, credential, HTTP, runtime consumer,
scheduler or permission to renew; future exact-source custody must save a choice
before use, never reroll on reads/restarts/restores. Unknown URLs never escape.

Guards: `TestARIInformationStrictBoundsCanonicalMeaningAndNoURLAuthority`,
`TestARIRetryAfterBoundsAndErrorPolicy`,
`TestARISelectionRandomWindowBackoffAndFallback`,
`TestARICertificateIDPreservesPositiveSerialPaddingAndHasNoTrustClaim`,
`TestRenewalPolicyCannotAcquireRuntimeOrNetworkAuthority`,
`FuzzARIInformation`, `FuzzARICertificateID`, `FuzzRenewalSelection`.

## C70 — ACME setup checking grants no network, storage or issuance authority

Retired on 23 November 2026 with the session-bound ACME automation
(ADR 0088): the staging setup route and its page are gone. The syntax check
in `internal/acmeplan` stays for Phase 3c and still grants no capability
(`TestACMEPlanChecksSyntaxWithoutGrantingCapabilities`).

## C71 — Staging directory reachability cannot become enrollment or arbitrary egress

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088):
the directory route, its consent and its page are gone. The directory client
in `internal/acmestaging` stays for Phase 3c with no runtime caller. It
still makes one pinned, secret-free TLS GET to a fixed host, dials public
addresses only, follows no proxy, redirect or retry, and parses a bounded
answer (`TestDirectoryDiscoveryUsesOnePinnedTLSGETWithoutSecrets`,
`TestDirectoryRefusesPrivateMixedDNSAndRevokedConsentBeforeDial`,
`TestDirectorySpecialAddressesAreDenied`,
`TestDirectoryResponseRefusalsNeverRetryOrReflect`,
`TestDirectoryStrictBoundedParser`,
`TestDirectoryTransportCannotFollowEndpointsOrSendTwice`,
`TestStagingLivePlatformBoundary`,
`TestStagingContainerSystemTrustWithoutNetwork`,
`FuzzStagingDirectory`). The offline Workbench still cannot import it
(`TestWorkbenchHasNoNetworkOrProcessImports`).

## C72 — Local staging account-key custody is not CA registration

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088):
the saved staging account key is gone with the old encrypted inventory
image. Account keys return in Phase 3c, as sealed vault records (C107).

## C73 — Same-key registration cannot become issuance or a blind retry

Retired on 23 November 2026 with the session-bound ACME automation
(ADR 0088): the registration route, its pending intent and the saved
account are gone. The registration client in `internal/acmestaging`
stays for Phase 3c with no runtime caller. It still sends only the
same-key JWS in at most three pinned requests, and refuses changed
terms, malformed or foreign answers and lost authority without a retry
(`TestRegistrationUsesRealSameKeyJWSAndOnlyThreePinnedRequests`,
`TestRegistrationTermsMismatchRefusesBeforeNonceAndPOST`,
`TestRegistrationStrictAbsentReconciliationNeverCreates`,
`TestRegistrationRefusesMalformedForeignAndUncertainAccountWithoutRetry`,
`TestRegistrationRefusesUnsafeDirectoryNonceAndLostAuthority`,
`TestRegistrationParentDeadlineBoundsStalledAccountBody`,
`FuzzStagingRegistrationResponse`).

## C69 — Saved-key attachment never overwrites or silently transfers a secret

ADR 0048 permits only adding a strict key to a saved certificate that has
none, under the exact generation and fingerprint. A saved key is never
replaced. The store repeats the check and keeps a mismatch only with an
explicit acknowledgement sealed with the key. Adding a key needs a signed-in
session and no fresh code, since it hands nothing out (C111); Check and Save
take the one slot for expensive checks. A key
check writes nothing. The certificate, its bundle, the time it was added and
its notes stay as they were; the key becomes a record of its own (C68).

The Certificates page checks a key first
and stops on a mismatch, and its Save never asks to keep one, so a key that
belongs to another certificate is not saved; Save revalidates on the server.
Errors are fixed messages, never server or file text. A key password that
does not open the key gets 422 with `X-Rootwell-Refusal: key-password-wrong`,
apart from a key that still needs one, so the page says the password is
wrong; the password field goes once the key opened or needs none.
Key/bundle/notes/trust
are never auto-transferred to another page; key/PFX conversion needs explicit
file selection in Convert. No CA/network/production claim follows.

Guarded by `TestAKeyAddedLaterIsCheckedFirstAndNeverReplaced`,
`TestAMismatchedKeyNeedsTheAcknowledgementAndOnlyThen`,
`TestKeyAttachmentRequestModesAreStrict`,
`TestLinuxAKeyAddedLaterIsCheckedAndNeverReplaced`,
`TestLinuxAWrongKeyPasswordIsNamed`,
`TestEncryptedKeyPairRequiresCorrectPassword`, and
`scripts/test-certificates.mjs`.

## C66 — Bulk preview is local and Save is exact and atomic

Retired on 22 November 2026 with the page rebuild: the bulk-import section of
the old Certificates page is gone. The inventory API's multi-certificate append
went on 23 November 2026 with the old encrypted inventory image; certificates
are added only through Save
(`TestLinuxCertificatesNeedAReadySessionAndThePageHeader`).

## C67 — Public lifecycle comparison/history and background checks stay scoped

The comparison core in `publicinventory` treats SAN, key, issuer and date
changes as information, never trust, and refuses private, mixed and malformed
input; output sizes and errors are bounded. The comparison and activity panels
of the old Certificates page were retired on 22 November 2026 with the page
rebuild.

On 23 November 2026, with the old encrypted inventory image (ADR 0088), the
comparison-source API, the encrypted activity history and the daemon's
background expiry check were retired too. The vault keeps no activity history
yet, and nothing checks expiry while nobody looks; the list works out the days
left when it is read (C64).

Guarded by `TestComparisonTracksAllNamesKeyAndDatesWithoutTrust`,
`TestComparisonRefusesPrivateMixedBundlesAndMalformed` and
`FuzzPublicComparison`.

## C74 — Access UI cannot claim a timed-out write or navigate on late results

Since 24 November 2026 the sign-in, setup and Account pages share one client
(`auth.js`). Each request is JSON to the same origin, with one fifteen-second
deadline for the whole exchange and at most 16 KiB of answer read. The pages
act on the status alone, and accept only the shapes the server sends on
success: a phone key of 32 base32 letters with its QR rows, and exactly ten
recovery codes in their printed form. They show fixed messages, never server
text. Each form runs one operation at a time. Sign-in takes the password and
the code out of their fields once read; setup empties its fields when the
phone step starts, and Account empties its fields when the page is left. A
timeout or a broken answer never counts as success, and cancelling cannot
undo a write the server already made.

Guarded by `scripts/test-rootwelld-auth.mjs`; the server side is C33 and
C108–C111. See ADR 0055. VM assertions are not browser visual QA.

## C75 — Manual DNS instructions cannot recreate an uncertain order or claim verification

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088):
the manual DNS order route, its saved order and its page are gone. The order
model in `internal/acmeorder` and the order client in `internal/acmestaging`
stay for Phase 3c with no runtime caller. Names and digests are still bounded
and canonical; only account-bound order requests go to the fixed staging
origin; unsafe locations, unapproved methods and late revocation are refused
without a retry (`TestManualDNSNamesURLsAndDigestAreBoundedCanonical`,
`TestManualDNSOrderUsesAccountBoundJWSAndPreservesBothTXTValues`,
`TestManualDNSOrderCheckpointsBeforeStalledOrMalformedBody`,
`TestManualDNSOrderRefusesUnsafeLocationFailedCheckpointAndAuthzWithoutRetry`,
`TestManualDNSOrderPreflightAndLateRevocationRefuseAuthority`,
`TestManualDNSJWSGuardRejectsWritePayloadAndUnapprovedDestination`,
`TestManualDNSTransportRefusesUnapprovedMethodsPathsAndBudgetBeforeIO`,
`FuzzManualDNSCAResponse`).

## C76 — CA DNS validation is explicit, complete and never blindly replayed

Retired on 23 November 2026 with the session-bound ACME automation
(ADR 0088): the DNS validation route and its saved intent are
gone. The validation code stays for Phase 3c with no runtime caller. A
verdict still needs a ready order and every authorization valid,
and Accept is sent only for the complete acknowledged scope, never
replayed (`TestValidationVerdictRequiresReadyAndEveryAuthorization`,
`TestDNSValidationAcceptsOnlyCompleteAcknowledgedScopeAndRefreshNeverWrites`,
`TestDNSValidationRejectsChangedOrPartialScopeBeforeAnyAccept`,
`TestDNSValidationMalformedAcceptClosesAuthorityWithoutRetryOrPartialOutput`,
`TestValidationChallengeParserNeverReflectsErrorsOrFollowsURLs`,
`TestValidationTransportRestrictsAcceptPayloadDestinationAndBudget`,
`TestDNSValidationLateRevocationAndCancellationReleaseNoResult`).

## C77 — Certificate request custody is bound, recoverable and not issuance

Retired on 23 November 2026 with the session-bound ACME automation
(ADR 0088): the saved certificate request and its route are
gone. The request builder in `internal/acmecertrequest` stays
for Phase 3c: exact names, a separate new key and strict refusal
(`TestCertificateRequestExactNamesSeparateKeyAndStrictRefusal`,
`FuzzCertificateRequestBinding`).

## C79 — Certificate protocol cannot poll, replay finalize or grant receipt trust

The internal staging connector rechecks exact prepared key/CSR and canonical
names before I/O and rejects account signer reuse. A current ready same-account
order plus COMPLETE all-valid authorization mapping precedes one finalize with
only that exact CSR. Refresh is POST-as-GET only, never finalize/new order/Accept.
Processing stops the maintained client's internal polling before even nonce
I/O; failed/lost replies yield zero observation and fixed refusal, not retries.
Every POST endpoint is single-use; failures close the operation. Twenty-second
and 23-request bounds, earliest expiry, fixed TLS/public-DNS numeric pinning,
no proxies/redirects/alternate/retry and live-permission checks apply. Unsafe
URLs, changed names/finalize/authz set, JWS scope, ambiguous JSON, headers and
mixed/duplicate/malformed/trailing/oversize public PEM refuse. Public PEM is
limited to five certificates, 48 KiB each, 256 KiB DER, 352 KiB wire before the
upstream parser; exact first envelope prevents garbage-skipping. A parsed receipt
is NOT trust or storage evidence: ADR 0058 plus locked atomic custody remains
mandatory. ADR 0062's live entry was retired on 23 November 2026 (C82); the
connector has no runtime caller until Phase 3c. No automatic
restart replay, live CA interoperability or audit claim.

Evidence: `TestCertificateConnectorExactCSRAccountJWSAndReadOnlyReconciliation`,
`TestCertificateConnectorProcessingNeverPollsOrRefinalizes`,
`TestCertificateGuardExactCSRAndDenyByDefault`,
`TestCertificateConnectorMaximumNamesFitExactRequestBudget`,
`TestCertificatePEMChainCountBoundary`, `FuzzCertificateCAResponse` and
`TestCertificateConnectorFixedStagingBoundary`. Synthetic TLS verifies
actual upstream JWS, including max-name 23-request success, read-only refresh,
lost finalize and no-poll processing; real receipt checker rejects its untrusted
test issuer. Two-direction sabotage and final gates are recorded in ADR 0059.

## C78 — Staging receipt acceptance cannot manufacture trust or widen a CSR

ADR 0058 adds only an offline internal gate, not finalize/issuance/storage/UI.
The exact bounded prepared P-256 key/CSR and canonical DNS set must match the
non-CA returned leaf. No extra/duplicate DNS, other SAN types (even types ignored
by crypto/x509), unknown key-usage bits, missing explicit signature/server usage,
unhandled critical extensions, algorithm/time/constraint failures or partial
results. Every bounded ordered response member must participate in the verified
path. Unknown, reordered, extraneous, duplicate or missing members refuse.
Trust comes only from four reviewed embedded, hash-checked self-signed staging
roots; no response/system root fallback, network or automatic root update.
RSA response keys above 8192 bits refuse before signature/path arithmetic;
bounded DER size alone is not a work-factor bound. Existing key floors remain.
Optional terminal root must be independently trusted, not merely self-signed.
Exact canonical wildcard SAN equality uses no synthetic hostname. Standard
X.509 verifies all SAN constraints and signatures. Result is public/test-only,
not order ownership, revocation, CT, deployment or ordinary browser trust.
Caller inputs are unchanged. Network/custody/UI integration and independent
production audit remain future work; can_issue is still false.

Guarded by `TestStagingReceiptExactBindingIndependentTrustAndNoInputMutation`,
`TestStagingReceiptRejectsAlteredNamesKeysUsageTimeAndSAN`,
`TestStagingReceiptRejectsTamperUntrustedExtraneousChainAndResourceAbuse`,
`TestStagingReceiptEnforcesEveryIssuerPolicyAndNameConstraints`,
`TestStagingReceiptDirectRootCrossSignedPathAndResponseBudget`,
`TestStagingReceiptCapsRSAIssuerWorkBeforeSignatureVerification`,
`TestStagingRootsExactOfficialAssetsAndNoFallback`,
`TestStagingReceiptHasNoNetworkStorageOrSigningAuthority` and
`FuzzStagingCertificateReceipt`; inherited request/policy/architecture tests.

## C81 — Atomic completion preserves the exact key and test-only origin

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088):
atomic staging completion is gone with the old encrypted inventory image.

## C80 — Durable issuance intent cannot mint a second first attempt

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088):
the saved issuance intent is gone. Phase 3c saves each step in the vault
before it is taken (ADR 0088).

## C82 — Interactive issuance cannot bypass durable exact-key custody

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088):
the interactive issuance route is gone. The certificate protocol stays
under C78 and C79, with no runtime caller until Phase 3c.

## C83 — A new request never revives or discards prior custody

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088):
closing a request and starting a new one are gone.

## C84 — Manual renewal never borrows or replaces the original key

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088):
manual staging renewal is gone.

## C85 — A renewal result cannot fabricate extension or replacement

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088):
the renewal result view is gone.

## C86 — Retry and DNS components cannot silently gain replay or cleanup authority

ADR 0066 only introduces testable components, not runtime automation. Retry
policy consumes a bounded attempt before I/O, rounds waits up, preserves longer
provider hints and refuses malformed clocks/state/hints or exhausted counts.
It cannot authorize CA creation/finalize replay. Cloudflare is unexported and
architecture-blocked before custody/UI. Fixed TLS/public DNS pinning, no proxy/
redirect/retry, exact one-zone TXT and intent-before-single-write; borrowed,
changed/foreign/ambiguous records cannot become cleanup-owned. Lost creation
only reads; 404 alone cannot fabricate absence. Concurrent provider edits are
not an atomic CAS guarantee. No new persisted field, route or runtime scheduler.

Guards: `TestRetryBudgetIntentBackoffProviderWaitAndExhaustion`,
`TestRetryPolicyRejectsMalformedClockHintsAndPartialState`,
`TestRetryDelayRoundsUpAndRejectsYearOverflow`, `FuzzProviderRetryAfter`,
`TestCloudflareTXTIntentBeforeWriteOwnExactRecordAndCleanup`,
`TestCloudflareExistingBorrowedAndUncertainCreateNeverBlindlyRetry`,
`TestCloudflareRefusesForeignChangedAmbiguousAndBareAbsence`,
`TestCloudflareCleanupAbsenceRequiresCompleteMatchingListAndNoDelete`,
`TestCloudflareRecordAliasesAndIncompletePaginationRefuseWithoutWrite`,
`TestCloudflareRevocationAfterIntentNeverTransmitsMutation`,
`TestCloudflareRefusesUnsafeScopePermitCommitTransportAndMalformedResponse`,
`TestCloudflareRateLimitHintNeverRetriesOrEchoesProviderBody`,
`FuzzCloudflareRecordResponse`,
`TestCloudflareProtocolHasOnlyReviewedFreshAuthConsumer` and inherited
fixed TLS/DNS/refusal tests. Actual two-way sabotage is recorded in ADR 0066/PR.

## C87 — DNS credential custody does not grant DNS or disclosure authority

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088):
the stored Cloudflare token is gone. DNS tokens return in Phase 3c, as
sealed vault records (C107).

## C88 — DNS attempts remain bound, durable and uncertain across recovery

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088):
the saved DNS plan is gone.

## C89 — Explicit Cloudflare operations retain exact owned scope and uncertainty

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088):
the Cloudflare DNS operations route is gone. The Cloudflare client stays
under C86, with no runtime caller until Phase 3c.

## C91 — Renewal readiness cannot manufacture renewal or recovery authority

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088):
the renewal readiness overview is gone with the hidden Renewals page.

## C90 — Exhausted DNS recovery is separate bounded read-only authority

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088):
the exhausted DNS recovery checks are gone.

## C68 — One certificate library does not collapse the secret boundary

ADR 0046 supersedes earlier no-custody statements only for the separate
certificate-library API. Inspect still rejects secret-bearing public input.
Ready Linux sessions may explicitly Check/Save one certificate and an optional
mathematically matching non-CA private key. Files, JSON and KDF concurrency
are bounded; Save revalidates identity and generation. Check is an own-daemon
upload and performs no write or trust verdict.

Since 23 November 2026 a saved certificate lives in the vault (C107) as two
sealed records: the certificate record holds the public certificates, the
notes and the key status; the key record holds only the key. Listing opens
certificate records only, never a key (audit RW-11); a download borrows the key
for one use and clears it. A record moved to another certificate's slot, or
holding unknown fields, is refused. Public output contains key presence and
status only. Note changes leave the key record alone; deletion removes both in
one transaction.

Private download requires a phone code from the last ten minutes (C111), the
exact displayed generation and fingerprint, and a final check that the same
signed-in session is still there. Only an encrypted PKCS#8 key, alone or with
the certificate in an unencrypted ZIP, is exposed here; there is no plaintext
custody export or reveal. The output password must meet the export policy.
The Certificates page checks each selection before Save and
forgets it on leaving the page. Untrusted parser, network and file error text
is never rendered. Copies of the data directory, compromised hosts and runtime
copies remain risks. This is single-operator development custody, not audited
production or RBAC.

ADR 0047 widened the matched-only scope: a saved certificate holds one selected
certificate, its bounded related public bundle and an optional strictly parsed
key. The page checks first; Save always revalidates. A computed mismatch is
kept only with an explicit acknowledgement sealed with the key, and is never
labelled matched. Ambiguous selection requires an exact supplied fingerprint;
issuer signatures are not trust. Matched-pair downloads refuse a mismatch; the
encrypted key-only download has the same fresh-code and output-password
gates. Included public bundle export does not establish
trust. Inspect's Check a private key uses a one-shot offline worker with no
save, export or network capability; a locked or unreadable key is never
reported as a mismatch. Inspect's certificate readers still refuse
secret-bearing input; since ADR 0089 the page first splits a file holding
certificates and a key (C115) and gives the key only to that one-shot check,
never showing it, and forgets it with the certificate.

Guarded by `TestPrepareCertificatePairsAndRefusals`,
`TestEncryptedKeyPairRequiresCorrectPassword`,
`FuzzPrepareRefusesSecretInCertificate`,
`TestBundleSelectionMatchMismatchAndIssuerRefusals`,
`FuzzBundleMatchRefusesMalformedKey`,
`TestAKeyIsSavedApartAndOnlyALoanOpensIt`,
`TestAMismatchedKeyNeedsTheAcknowledgementAndOnlyThen`,
`TestDeleteTakesTheKeyWithIt`,
`TestARecordMovedToAnotherCertificateIsRefused`,
`TestStoredRecordsHoldNoUnknownFields`,
`TestCertificateRequestModesRejectMalformedAndAmbiguousJSON`,
`TestCertificateRequestBoundsAndDownloadMode`,
`TestLinuxCertificatesLiveInTheVaultAndSurviveARestart`,
`scripts/test-certificates.mjs`, `scripts/test-inspect.mjs`,
`scripts/test-convert.mjs` and actual key-match Go WASM assertions in
`scripts/test-browser-csr.mjs`.
