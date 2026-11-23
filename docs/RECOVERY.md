# Rootwell recovery on Linux

**Status:** development design.

- Two things open an installation:
  - the **instance key file**, which opens the certificate vault
    (`rootwell.db`);
  - the **sign-in password** in `access.json`, which only signs in. It
    unlocks no data.
- Phase 3b of `PRODUCT-PLAN.md` adds backups and restores started from the
  Installation page, and key rotation. Until then, this page is the procedure.
- On Windows these commands are deliberately disabled.

Passwords and recovery codes are never accepted as command arguments or
environment variables. Every command asks for them on the local terminal. Keep
them out of shell history, chat, tickets and logs, and protect the terminal's
scrollback.

## Setup

The key file lives in its own private directory, **outside** the data
directory, so a copy of the data never carries its key. `init` and `serve`
refuse a key file inside the data directory.

```text
install -d -m 0700 /private/rootwell-key
rootwelld init /private/rootwell-data /private/rootwell-key/instance.key
```

`init` shows two things once:

1. the **setup password**. Sign in with it, then change it;
2. the **instance key's recovery code**: `RW1-` and groups of letters and
   digits.

Type `SAVED` once both are kept. Only then does `init` write the key file
(`0600`), create the vault and create `access.json`. It never replaces an
existing key file or installation.

Keep the recovery code offline, apart from this host and from every backup. It
is the key file's only backup. **Losing both the key file and the code loses
every saved certificate and key.**

Then start the service:

```text
rootwelld serve /private/rootwell-data /private/rootwell-key/instance.key web/workbench
```

## Backup

Online backup comes in Phase 3b. Until then, copy the data directory with the
service stopped:

```text
# stop rootwelld serve first
cp -a /private/rootwell-data /private/backup/rootwell-data-2026-11-24
```

- The copy holds `rootwell.db` and `access.json`. Every certificate and key in
  it is sealed; without the key file or the recovery code it opens nothing.
- **Never copy the key file to the backup location.** The recovery code, kept
  apart, is the key's backup.
- Copy while the service runs and the copy may be incomplete: stop it first.
- Make a new copy after changes you want to keep, under a new name. Rootwell
  makes no automatic backups.

## Restore

Restore into a new, empty `0700` directory, **never the live one**:

```text
install -d -m 0700 /private/rootwell-data-restored
cp -a /private/backup/rootwell-data-2026-11-24/. /private/rootwell-data-restored/
```

- `rootwell.db` and `access.json` must stay `0600` and owned by the service
  user; `cp -a` keeps that. The vault refuses a directory or file that others
  can read.
- If the key file still exists, start `serve` with the restored directory and
  the same key file.
- If the key file is lost too, rebuild it, then start `serve`:

  ```text
  install -d -m 0700 /private/rootwell-key
  rootwelld key-restore /private/rootwell-data-restored /private/rootwell-key/instance.key
  ```

- Sign in with the password that was current when the copy was made.
- An older copy brings back certificates deleted since; Rootwell does not
  detect that.

## Lost key file

`key-restore` rebuilds a lost key file from the recovery code:

```text
rootwelld key-restore /private/rootwell-data /private/rootwell-key/instance.key
```

- Stop the service first: it holds the vault, and `key-restore` refuses while
  it runs.
- It asks for the code on the terminal, and checks that the code opens the
  vault in that data directory before writing anything. A code from another
  installation is refused.
- It never replaces an existing key file. The key directory must be `0700`.

## Sign-in password

These commands work on `access.json` alone. They concern the sign-in password
only; they do not protect or back up certificates. Stop the service first: a
Linux operation lock refuses them while it runs.

The **password recovery code** they use is a different code from the instance
key's recovery code.

1. Once the setup password has been changed, create it:

   ```text
   rootwelld recovery-enroll /private/rootwell-data
   ```

   Keep it offline, apart from the data and the backups. If you lose it but
   still know the password, `recovery-rotate` makes a new one.
2. If the password is lost, set a new one with the code:

   ```text
   rootwelld recovery-reset /private/rootwell-data
   ```

   This also prints a new code; the old one stops working.
3. An access-only snapshot holds `access.json` alone, never certificates:

   ```text
   rootwelld access-snapshot /private/rootwell-data /private/backup/rootwell-access.rwab
   rootwelld access-verify /private/backup/rootwell-access.rwab code
   rootwelld access-restore /private/backup/rootwell-access.rwab /private/fresh-rootwell-data code
   ```

   - The snapshot needs both the password and the code, is written `0600`
     and never replaces a file.
   - `access-restore` writes only into a new, empty `0700` directory.

After a failed or `uncertain` result, do not repeat a command blindly: first
look at the directory.

The Docker procedure is in [`CONTAINER-RECOVERY.md`](CONTAINER-RECOVERY.md).
