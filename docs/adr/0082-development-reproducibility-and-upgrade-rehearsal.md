# ADR 0082 — Development build proof and upgrade/restore rehearsal

Date: 2026-11-02. Release preparation, not publication or an audit verdict.

The fourth authorised stage needs a reproducible candidate and an operational
path from an existing encrypted installation to a checked replacement. Current
container CI already exercises private volumes, restart, a busy writer,
networkless maintenance and fresh-volume full recovery. Add a complete
independent-build proof and a single operator runbook; do not substitute a
same-binary restart for a cross-version upgrade claim. The container drill
requires the platform event's exact previous protected-base SHA, fetches that
object from the same repository, builds its existing fixture binary and seeds
the disposable volume/backup with that older code. Candidate fixture/daemon
then reopen, serve and restore it. Missing/zero/malformed baseline or a failed
seed fails the job. This proves only adjacent-commit fixture compatibility,
not arbitrary prior versions, real operator data or live provider continuity.

`scripts/test-reproducible-build.sh` runs only on isolated Linux amd64 with
`RUNNER_TEMP`. It requires a clean index/tracked worktree and an exact commit,
archives only that Git revision, extracts two independent source directories
and uses separate clean build caches. Both builds use the exact go.mod
toolchain, verified cached modules, disabled module/toolchain downloads,
CGO disabled, trimpath, no VCS metadata and an empty build ID. The CLI, Linux
daemon, browser WASM and pinned toolchain's WASM runtime must match byte for
byte. Changed/missing output sabotage must be detected, then restored output
must pass again. Only public artifact hashes and the source revision are
printed; no instance path, data key, token, password, signing key or recovery
code is an input. Temporary source/build artifacts are removed on exit.

The proof runs in the existing required Build and test job. It does not tag,
sign, upload, publish or deploy. This is a pinned Linux development build proof,
not reproducibility across Go versions, operating systems, compiler binaries,
container image metadata or a malicious compiler. Commit/tag signature trust
and an independently audited release candidate remain separate gates.

The operator runbook distinguishes evidence already available from pending
cross-version/live-provider tests. Before upgrade: stop the daemon, verify a
new complete encrypted backup using the offline recovery method, keep the old
binary/image and its source identity, restore into a distinct empty directory,
then check login, matched pairs, notes/history, expiry and pending ACME/DNS
states locally. Restored unknown writes remain unknown; no job/session grant
survives. Do not send another CA/DNS operation as a health check. Upgrade the
original only after the restored candidate passes. Rollback after any new
write requires restoring the old complete snapshot into another empty volume
with its compatible old binary; never point an old binary at newer data or
claim later writes survived rollback. No destructive automated migration.

No external audit is performed by this implementation. The handoff must name
the exact candidate and provide engineering rules, threat models, invariants,
relevant PRs, final-head checks and reproducible build/recovery evidence.
Material findings must be fixed and rechecked before any first public release.
Production custody/UI and live ACME interoperability remain separate open work.

Local pre-commit evidence: Bash syntax, actionlint, existing container policy
tests and executable baseline/proof guard refusals passed on Windows Git Bash.
The invalid baseline tests run without Docker or network and must not echo the
supplied value. Real independent Linux builds, altered/missing artifact checks,
adjacent-base container seed/reopen/serve/restore and the full required suite
are CI gates, not claimed as locally executed on this Docker-free host.
