# Rootwell upgrades, rollback and release preparation

**Status:** development. Nothing has been released. An independent audit comes
before the first release (`ENGINEERING.md`).

The install and backup commands are in
[`CONTAINER-RECOVERY.md`](CONTAINER-RECOVERY.md). Phase 3e of
`PRODUCT-PLAN.md` replaces this procedure with upgrade scripts like Keybash's.

## Evidence CI produces today

- **Container volumes:**
  - a restart;
  - refusal of a busy writer;
  - offline maintenance with no network;
  - secret output kept out of Docker logs, and a setup code kept out of the
    server's log.
- **Upgrade drill:** the test binary of the protected base commit creates a
  synthetic volume; the candidate opens it and serves it. This proves
  compatibility between those two commits only. A restore into an empty
  volume returns with online backup in Phase 3b.
- **Reproducible build:** two separate checkouts and build caches build the
  same commit. Their outputs must match byte for byte for:
  - the CLI;
  - the Linux daemon;
  - the WebAssembly engine;
  - its runtime.

  A changed or missing output fails the check.

None of this is a cross-version upgrade on a real host, a live CA or
Cloudflare test, or an independent audit.

## Before an upgrade

1. Record the running source commit and the binary or image ID. Keep the old
   image and its Compose file. A mutable `latest` tag is not a way back.
2. Sign out and stop the daemon.
3. Copy the data directory under a new name, as in
   [`RECOVERY.md`](RECOVERY.md). Keep the key file and its recovery code; the
   copy carries neither.
4. Leave the live data directory untouched. Restore the copy into another
   empty `0700` directory and try the candidate there first.

## Checks on the restored candidate

| Page | Expected |
|---|---|
| Sign-in and Account | The account's password and a phone code sign in; a key download asks for a fresh code; sign-out works |
| Certificates | The same fingerprints, key status, bundles and notes |
| Expiry | Dates computed from the server's current clock |
| Inspect, Convert, Request | A synthetic file inspects and converts correctly, and a request is made |
| Backup | A new copy from the candidate opens in another empty directory |

When every check passes, repeat on the original installation:

1. Stop the daemon.
2. Make a new copy of the data directory.
3. Start the candidate.

## Rolling back

The safe way back has three parts:

- the old binary or image;
- the backup taken before the upgrade;
- **another empty data directory**.

Never give a volume the new version has written to the old binary.

Returning to a backup does not bring back anything done after it: imports,
notes, keys, and ACME or DNS results. Work already done at the CA or the DNS
provider is not undone by a disk rollback. Reconcile it with the provider
before acting again.

## Handing a candidate to an auditor

- the exact commit, its signature and every CI run for it;
- [`ENGINEERING.md`](ENGINEERING.md) and the threat models, including
  [`THREAT-MODEL.md`](THREAT-MODEL.md);
- [`SECURITY-INVARIANTS.md`](SECURITY-INVARIANTS.md);
- the sabotage, refusal, fuzz, race, reproducible-build and restore results;
- the known limits: one account, Linux loopback, sessions of at most
  8 hours, and no rollback detection.

Never include secrets, real backups, tokens, passwords, codes or private keys.
A release is not called audited while a material finding is open.
