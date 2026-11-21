# Rootwell recovery on Linux

**Status:** development design.

- These terminal commands protect today's password-derived installation.
- Phase 3 of `PRODUCT-PLAN.md` replaces them with an instance key and backups
  started from the Installation page.
- On Windows these commands are deliberately disabled.

Passwords and recovery codes are never accepted as command arguments or
environment variables. Every command asks for them on the local terminal. Keep
them out of shell history, chat, tickets and logs, and protect the terminal's
scrollback.

## Access only

An access snapshot holds only `access.json`. It does not hold certificates or
keys; for those, see the full snapshot below.

1. Stop `rootwelld serve`. The Linux operation lock refuses offline work while
   the daemon runs.
2. Create the recovery code once:

   ```text
   rootwelld recovery-enroll /private/rootwell-data
   ```

   - Keep the code offline, away from the data, the backups and this host.
   - If you lose it but still know the password, `recovery-rotate` makes a
     new one. Old backups still accept the old code.
3. Prepare a separate `0700` backup directory, then:

   ```text
   rootwelld access-snapshot /private/rootwell-data /private/backup/rootwell-access.rwab
   rootwelld access-verify /private/backup/rootwell-access.rwab code
   ```

   - The snapshot needs both the password and the code.
   - It is written with mode `0600` and never replaces an existing file.
   - Keep it off-site, and never next to the code.
4. To rehearse a restore, use a new, empty `0700` directory, **never the live
   one**:

   ```text
   rootwelld access-restore /private/backup/rootwell-access.rwab /private/fresh-rootwell-data code
   rootwelld recovery-reset /private/fresh-rootwell-data
   ```

   - The restore keeps the old password.
   - `recovery-reset` sets a new password and a new code, if the old password
     is lost. Make a new snapshot afterwards.

If both the password and the code are lost, the encrypted data cannot be
recovered.

After a failed or `uncertain` result, do not repeat the command blindly:
first look at the directory.

The format does not detect rollback: an older but genuine snapshot can be
restored.

## Certificates: full snapshot and restore

Linux only, with the daemon stopped. First:
- enrol a recovery code;
- prepare a private `0700` backup directory.

Activating the store writes a full snapshot of the empty store **before**
creating it:

```text
rootwelld inventory-init /private/rootwell-data /private/backup/initial.rwfull
rootwelld inventory-verify /private/backup/initial.rwfull code
```

Start the daemon and sign in; the Certificates page then works.

After any change, stop the daemon and write a new snapshot under a new name.
Changes include an import, a note, a location, a deletion, an ACME step, a
password change or a code change. Existing files are never replaced.

```text
rootwelld inventory-snapshot /private/rootwell-data /private/backup/dated.rwfull
rootwelld inventory-verify /private/backup/dated.rwfull password
```

To restore into a new, empty `0700` directory:

```text
rootwelld inventory-restore /private/backup/dated.rwfull /private/fresh-rootwell-data code
rootwelld recovery-reset /private/fresh-rootwell-data
```

- The restore checks the access envelope and the store together before writing
  anything, and never replaces an existing installation.
- If a restore stops halfway, inspect that directory and retry into another
  new one.
- A snapshot keeps the password and code that were current when it was made.
  Change both after a restore and make a new snapshot.
- Snapshots reveal metadata such as certificate fingerprints. Store them and
  the code in separate places.

The Docker procedure is in [`CONTAINER-RECOVERY.md`](CONTAINER-RECOVERY.md).
