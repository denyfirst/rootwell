# Rootwell with Docker on Linux: private volumes and recovery

**Status:** development design.

- `compose.yaml` is for local use and testing on a Linux host.
- Phase 3e of `PRODUCT-PLAN.md` replaces these steps with an install script.

The daemon answers over HTTPS on port 4180 of the host's loopback addresses,
`127.0.0.1` and `[::1]`, and on a LAN address only when you add one
([below](#reach-rootwell-from-another-machine)). `network_mode: host` lets it
do so, at the cost of the container's network isolation. Do not expose
Rootwell to the internet.

The image takes the public CA bundle from its pinned base image. It installs
no staging or test roots in the system trust. Maintenance containers have no
network.

## First setup

On a Linux host you control, choose **three different** absolute directories:
one for data, one for the instance key and one for backups. None may be inside
another, or on the same volume as the backups.

```sh
export ROOTWELL_UID="$(id -u)" ROOTWELL_GID="$(id -g)"
export ROOTWELL_DATA_DIR=/srv/rootwell-private/data
export ROOTWELL_KEY_DIR=/srv/rootwell-key/private
export ROOTWELL_BACKUP_DIR=/srv/rootwell-backup/private
install -d -m 0700 "$ROOTWELL_DATA_DIR" "$ROOTWELL_KEY_DIR" "$ROOTWELL_BACKUP_DIR"
docker compose build rootwell
docker compose run --rm maintenance init /data /key/instance.key
```

1. The terminal shows, once, the instance key's recovery code (`RW1-` and
   groups of letters and digits). Type `SAVED` once it is kept. Then it
   prints a setup code for the first account, which works once, for 24 hours.
2. Keep the recovery code offline, apart from this host and from the backups.
   It is the key file's only backup. Losing both the key file and the code
   loses every saved certificate and key.
3. Start the service with `docker compose up -d rootwell`. The image runs
   `serve /data /key/instance.key /assets`; the service mounts `/key`
   read-only. Its first start makes Rootwell's own certificate authority, and
   `docker compose logs rootwell` shows the authority's SHA-256 fingerprint.
4. Trust that authority in your browser, checking the fingerprint, as in
   [`RECOVERY.md`](RECOVERY.md#trust-rootwells-certificate-authority).
5. Open `https://localhost:4180/setup` on the same host. Enter the setup code,
   a name and a password of at least 15 characters. Add Rootwell to an
   authenticator app on your phone and enter the code it shows, then save the
   ten recovery codes, which are shown only once.

The maintenance service uses `logging.driver: none`, so the codes it prints
never reach Docker's logs; a TTY alone would not prevent that. If you run the
image outside Compose, pass `--log-driver none` yourself.

If the setup code runs out before it is used, make a new one:

```sh
docker compose stop rootwell
docker compose run --rm maintenance setup-code /data /key/instance.key
docker compose up -d rootwell
```

## Reach Rootwell from another machine

By default Rootwell answers only on the host itself. To reach it over the LAN
or a VPN, add the host's address, and any DNS name that leads to it, to
Rootwell's names. `192.168.1.5` is an example:

```sh
docker compose stop rootwell
docker compose run --rm -T maintenance serving-names /data /key/instance.key 192.168.1.5
```

Then tell the service to listen on that address, with a
`compose.override.yaml` next to `compose.yaml`; Compose reads it by itself:

```yaml
services:
  rootwell:
    command: ["serve", "/data", "/key/instance.key", "/assets", "--listen", "192.168.1.5"]
```

```sh
docker compose up -d rootwell
```

- Every change of names makes a **new certificate authority**, and
  `serving-names` prints its fingerprint. Trust the new one on every
  computer, and remove the old one.
- `--listen` takes only an address the names cover; otherwise the service
  does not start, and `docker compose logs rootwell` says why.
- Then open `https://192.168.1.5:4180` from the other machine.
- `serving-names` with no names goes back to the host only; remove the
  override file too. The rules for names are in
  [`RECOVERY.md`](RECOVERY.md#reach-rootwell-from-another-machine).

## Lost phone, passkey or password

Passkeys, added on the Account page, stand in for the phone code; how they
work, and why they need a DNS name rather than an IP address, is in
[`RECOVERY.md`](RECOVERY.md#passkeys).

- **Lost phone:** sign in with one of the recovery codes in place of the
  phone code. Then, on the Account page, move to a new phone, or make new
  recovery codes if few are left. Either one signs out every other browser.
- **Lost passkey device:** sign in with the phone code, or a recovery code,
  and remove its passkey on the Account page. That signs out every other
  browser.
- **Lost password, or lost phone and recovery codes:** make a setup code for
  the account, with its name (`ada` here), and use it on `/setup` with the
  same name and a new password:

  ```sh
  docker compose stop rootwell
  docker compose run --rm maintenance setup-code /data /key/instance.key ada
  docker compose up -d rootwell
  ```

  It replaces the password, the phone and the recovery codes, removes every
  passkey, since the device that holds one may be lost too, and leaves the
  certificates alone. The code works once, for 24 hours, and only for that
  name.

## Backup

On the **Installation** page, in the menu under Account, choose **Download a
backup**. Rootwell asks for a code from the phone, a recovery code or a
passkey, unless you entered one in the last ten minutes, and the browser
saves `rootwell-backup-<date and time>.db`. The service keeps running.

- The backup is a consistent copy of the whole vault: every certificate and
  key, the account, its passkeys and Rootwell's certificate authority, all
  sealed. It holds no instance key, so it opens only with the key Rootwell
  had when it was made, or that key's recovery code.
- Keep it off-site, apart from the recovery code. To restore it, copy it into
  `ROOTWELL_BACKUP_DIR`, readable by the same UID.
- Rootwell makes no automatic backups. Make a new one after changes you want
  to keep, and rehearse a restore from time to time.

The page hands out up to 64 MiB. A larger vault is copied on the host with
the service stopped:

```sh
docker compose stop rootwell
cp -a "$ROOTWELL_DATA_DIR/rootwell.db" "$ROOTWELL_BACKUP_DIR/rootwell-backup-2026-11-24.db"
docker compose up -d rootwell
```

**Never copy `ROOTWELL_KEY_DIR` to the backup location.** The recovery code
is the key's backup.

## Restore on a clean volume

`restore` writes a backup only into an empty data directory, so point
`ROOTWELL_DATA_DIR` at a new one owned by the same UID, and keep the old one
until the restored Rootwell works. The backup must be in
`ROOTWELL_BACKUP_DIR`, which the container sees as `/backup`; its name below
is an example:

```sh
docker compose stop rootwell
export ROOTWELL_DATA_DIR=/srv/rootwell-private/restored
install -d -m 0700 "$ROOTWELL_DATA_DIR"
docker compose run --rm maintenance restore /backup/rootwell-backup-20261124T120000Z.db /data /key/instance.key
docker compose up -d rootwell
```

- The maintenance container sees `/backup` read-only: `restore` only reads
  the backup, and nothing run there can change or remove one.
- `restore` keeps the backup only if it opens with `/key/instance.key`;
  otherwise it leaves `/data` empty. A backup opens only with the key the
  vault had when it was made: after a key rotation, an older backup needs the
  old key, or its old recovery code.
- **If the key file is lost too,** point `ROOTWELL_KEY_DIR` at an empty `0700`
  directory owned by the same UID first. `restore` then asks for the instance
  key's recovery code, and writes the key file from it once the backup opens
  with it.
- A copy made on the host restores the same way.

The account comes back as it was when the backup was made: sign in again,
with the password and phone of that time, and check that the certificates
are there. If those are lost, make a setup code with the account's name, as
above. The certificate authority and its names come back as they were too,
and so do the account's passkeys: on the Account page, remove again any you
removed since the backup.

## Lost key file

If the key file is lost but the data directory is not, point
`ROOTWELL_KEY_DIR` at an empty `0700` directory owned by the same UID, and
rebuild the key file from the recovery code before starting the service:

```sh
docker compose stop rootwell
docker compose run --rm maintenance key-restore /data /key/instance.key
docker compose up -d rootwell
```

- It asks for the code on the terminal and checks that the code opens the
  vault in `/data` before writing anything. A code from another installation
  is refused.
- It refuses while the service runs, because the service holds the vault.
- It never replaces an existing key file.

## Move to a new instance key

Move to a new instance key when the key file or its recovery code may have
been seen or copied:

```sh
docker compose stop rootwell
docker compose run --rm maintenance key-rotate /data /key/instance.key
docker compose up -d rootwell
```

- It shows the new key's recovery code once. Type `SAVED` once it is kept;
  until then nothing changes. It then moves the vault to the new key in one
  step, rewrites its file so nothing left in it opens with the old key, and
  puts the new key file in place of the old one. Everything in the vault
  stays as it was.
- **Backups made before keep opening with the old key and its old recovery
  code only.** Keep the old code as long as you keep those backups, and make
  a new backup after rotating.
- If it is interrupted, the next `key-rotate` finds `instance.key.new` beside
  the key file, refuses and says what to do, as in
  [`RECOVERY.md`](RECOVERY.md#move-to-a-new-instance-key).

## Show the recovery code again

`key-export` prints the recovery code of the key in `/key/instance.key`, once
it has checked that the key opens the vault:

```sh
docker compose stop rootwell
docker compose run --rm maintenance key-export /data /key/instance.key
docker compose up -d rootwell
```

## What CI proves

`scripts/test-container-volume.sh` runs only in CI's disposable
`RUNNER_TEMP`. It creates four bind mounts (data, key, backup and a scratch
directory for the test) and checks:

- a volume seeded by the base commit (or by the candidate, when the base
  predates the vault) reopens in a new container with the candidate: the saved
  certificate and its key come back, a change is accepted, and another key is
  refused;
- the service starts on it and mounts only `/data` and `/key`;
- it serves `/rootwell-ca.pem`, and its sign-in page verifies against that
  authority over TLS 1.3, after the first start and after a restart;
- a second opener is refused while the service holds the vault;
- a data directory others can read is refused;
- the service restarts on the same volume;
- maintenance output never reaches `docker logs`;
- when the seed writes a setup code, the server's log never holds it.

The drill does not restore a backup yet. `rootwelld restore` has its own
tests, and a backup from the Installation page was restored through the
maintenance container on a test machine by hand (`STATUS.md`). This does not
cover every storage fault, a compromised host or off-site durability.
