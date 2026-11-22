# Rootwell with Docker on Linux: private volume and full restore

**Status:** development design.

- `compose.yaml` is for local use and testing on a Linux host.
- Phase 3 of `PRODUCT-PLAN.md` replaces these steps with an install script and
  backups started from the Installation page.

The daemon binds only `127.0.0.1:4180` on the host. `network_mode: host`
lets the host's browser reach it, at the cost of the container's network
isolation. Do not expose Rootwell to the internet.

The image takes the public CA bundle from its pinned base image. It installs
no staging or test roots in the system trust. Maintenance containers have no
network.

## First setup

On a Linux host you control, choose **two different** absolute directories,
one for data and one for backups. They must not be the same directory or the
same volume.

```sh
export ROOTWELL_UID="$(id -u)" ROOTWELL_GID="$(id -g)"
export ROOTWELL_DATA_DIR=/srv/rootwell-private/data
export ROOTWELL_BACKUP_DIR=/srv/rootwell-backup/private
install -d -m 0700 "$ROOTWELL_DATA_DIR" "$ROOTWELL_BACKUP_DIR"
docker compose build rootwell
docker compose run --rm maintenance init /data
```

1. The setup password appears only on the interactive terminal. Type `SAVED`
   to confirm.
2. Start the service with `docker compose up -d rootwell`.
3. Open `http://localhost:4180` on the same host and change the setup
   password, which is mandatory.
4. Stop the service again.

```sh
docker compose stop rootwell
docker compose run --rm maintenance recovery-enroll /data
docker compose run --rm maintenance inventory-init /data /backup/initial.rwfull
docker compose run --rm maintenance inventory-verify /backup/initial.rwfull code
docker compose up -d rootwell
```

Keep the recovery code offline, apart from the data, the backups and the
host.

The maintenance service uses `logging.driver: none`, so the setup password
and the code never reach Docker's logs; a TTY alone would not prevent that. If
you run the image outside Compose, pass `--log-driver none` yourself.

## A backup after every change

Stop the daemon, then write a snapshot under a new name:

```sh
docker compose stop rootwell
docker compose run --rm maintenance inventory-snapshot /data /backup/2026-11-22-01.rwfull
docker compose run --rm maintenance inventory-verify /backup/2026-11-22-01.rwfull code
docker compose up -d rootwell
```

- An access snapshot does **not** hold certificates.
- Rootwell makes no automatic backups.
- Copy snapshots off-site and rehearse restores from time to time.

## Restore rehearsal on a clean volume

Prepare a new, empty `0700` data directory owned by the same UID. Point
`ROOTWELL_DATA_DIR` at it, and keep the old volume.

```sh
docker compose stop rootwell
export ROOTWELL_DATA_DIR=/srv/rootwell-private/fresh-drill
install -d -m 0700 "$ROOTWELL_DATA_DIR"
docker compose run --rm maintenance inventory-verify /backup/2026-11-22-01.rwfull code
docker compose run --rm maintenance inventory-restore /backup/2026-11-22-01.rwfull /data code
docker compose up -d rootwell
```

Check in the browser that the restored records are there. If the old password
is lost:

1. Stop the service.
2. Run `docker compose run --rm maintenance recovery-reset /data`.
3. Make a new full snapshot.

## What CI proves

`scripts/test-container-volume.sh` runs only in CI's disposable
`RUNNER_TEMP`. It creates four bind mounts (data, backup, fresh and test
recovery) and checks:

- an import survives a restart;
- a full snapshot can be made;
- a wrong code and a damaged backup are refused;
- an offline backup is refused while the daemon runs;
- a data directory with loose permissions is refused;
- a restore into a clean volume works, and the page opens from it;
- the service container mounts only `/data`;
- maintenance output never reaches `docker logs`.

This does not cover every storage fault, a compromised host or off-site
durability.
