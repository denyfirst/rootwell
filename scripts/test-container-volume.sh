#!/usr/bin/env bash
set -euo pipefail

# CI-only disposable material. Never point this drill at an operator volume.
if [[ -z "${RUNNER_TEMP:-}" || ! -d "$RUNNER_TEMP" ]]; then
  echo "RUNNER_TEMP is required for an isolated disposable drill" >&2
  exit 1
fi
if [[ ! "${ROOTWELL_UPGRADE_BASE:-}" =~ ^[0-9a-f]{40}$ ||
      "$ROOTWELL_UPGRADE_BASE" == 0000000000000000000000000000000000000000 ]]; then
  echo "An exact previous protected-base commit is required for the upgrade drill" >&2
  exit 1
fi
docker compose version >/dev/null
drill_root="$(mktemp -d "${RUNNER_TEMP}/rootwell-volume-XXXXXXXX")"
if [[ "$drill_root" != "${RUNNER_TEMP}/rootwell-volume-"* ]]; then
  echo "unexpected drill directory" >&2
  exit 1
fi
cleanup() {
  if [[ -n "${maintenance_probe_id:-}" ]]; then
    docker rm -f "$maintenance_probe_id" >/dev/null 2>&1 || true
  fi
  docker compose -f compose.yaml -p rootwell-volume-ci down --remove-orphans >/dev/null 2>&1 || true
  rm -rf -- "$drill_root"
}
trap cleanup EXIT

mkdir "$drill_root/data" "$drill_root/key" "$drill_root/backup" "$drill_root/recovery"
chmod 0700 "$drill_root" "$drill_root/data" "$drill_root/key" "$drill_root/backup" "$drill_root/recovery"
export ROOTWELL_UID="$(id -u)" ROOTWELL_GID="$(id -g)"
export ROOTWELL_DATA_DIR="$drill_root/data" ROOTWELL_KEY_DIR="$drill_root/key" ROOTWELL_BACKUP_DIR="$drill_root/backup"

# Adjacent-version upgrade: seed with the previous protected base's fixture
# binary, then reopen and serve with the candidate. No instance or external
# provider is contacted. The platform event supplies only an exact SHA. A base
# from before the vault has no drill for it; then the candidate seeds, since
# earlier development data is not carried forward (ADR 0088).
git fetch -q --depth 1 origin "$ROOTWELL_UPGRADE_BASE"
if [[ "$(git rev-parse FETCH_HEAD)" != "$ROOTWELL_UPGRADE_BASE" ]]; then
  echo "Upgrade baseline revision did not match" >&2
  exit 1
fi
mkdir "$drill_root/baseline-source"
git archive "$ROOTWELL_UPGRADE_BASE" | tar -xf - -C "$drill_root/baseline-source"
seed_image=rootwell-volume-drill:ci
if [[ -f "$drill_root/baseline-source/internal/certstore/volume_drill_linux_test.go" ]]; then
  docker build --target volume-drill -t rootwell-volume-baseline:ci "$drill_root/baseline-source"
  seed_image=rootwell-volume-baseline:ci
else
  echo "The base ${ROOTWELL_UPGRADE_BASE} predates the vault; the candidate seeds the volume."
fi
docker build --target volume-drill -t rootwell-volume-drill:ci .
docker build -t rootwell:local .
docker build --target ca-trust-drill -t rootwell-ca-trust-drill:ci .
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --env ROOTWELL_CA_TRUST_DRILL=1 rootwell-ca-trust-drill:ci \
  -test.run '^TestStagingContainerSystemTrustWithoutNetwork$' -test.v
# Availability sabotage in a separate offline process: hide both root sources.
if trust_failure="$(docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --env ROOTWELL_CA_TRUST_DRILL=1 \
  --env SSL_CERT_FILE=/missing/rootwell-ca.pem --env SSL_CERT_DIR=/missing/rootwell-certs \
  rootwell-ca-trust-drill:ci -test.run '^TestStagingContainerSystemTrustWithoutNetwork$' -test.v 2>&1)"; then
  echo "missing-root sabotage was not detected" >&2
  exit 1
fi
if ! grep -Fq 'serving trust-base has no loadable system roots' <<< "$trust_failure"; then
  echo "missing-root drill failed for an unexpected reason" >&2
  exit 1
fi
docker compose -f compose.yaml -p rootwell-volume-ci config --quiet
if [[ "$(docker image inspect --format '{{.Config.User}}' rootwell:local)" != "65532:65532" ]]; then
  echo "production image must default to a non-root user" >&2
  exit 1
fi
docker compose -f compose.yaml -p rootwell-volume-ci --profile maintenance config --format json \
  | node scripts/check-container-config.mjs

# Public usage output, never an actual credential. Prove attached output still
# works while Docker's container log driver cannot retain it. -T prevents a CI
# terminal requirement; the production maintenance service still requires TTY.
maintenance_probe_name="rootwell-maintenance-${drill_root##*/}"
probe_exit=0
probe_output="$(docker compose -f compose.yaml -p rootwell-volume-ci run \
  --name "$maintenance_probe_name" --no-deps -T maintenance logging-drill 2>&1)" || probe_exit=$?
maintenance_probe_id="$(docker inspect --format '{{.Id}}' "$maintenance_probe_name")"
if [[ "$probe_exit" != 2 ]] || ! grep -Fq 'usage: rootwelld init' <<< "$probe_output"; then
  echo "maintenance attached public-output probe failed" >&2
  exit 1
fi
if [[ "$(docker inspect --format '{{.HostConfig.LogConfig.Type}}' "$maintenance_probe_id")" != "none" ]]; then
  echo "maintenance container may retain interactive secrets" >&2
  exit 1
fi
probe_logs="$(docker logs "$maintenance_probe_id" 2>&1)" || true
if grep -Fq 'usage: rootwelld init' <<< "$probe_logs"; then
  echo "maintenance output was available through Docker logs" >&2
  exit 1
fi
docker rm "$maintenance_probe_id" >/dev/null
maintenance_probe_id=''

volume_test() {
  local phase="$1"
  local fixture_image="${2:-rootwell-volume-drill:ci}"
  docker run --rm --network none --user "${ROOTWELL_UID}:${ROOTWELL_GID}" \
    --read-only --cap-drop ALL --security-opt no-new-privileges \
    --mount "type=bind,src=${drill_root}/data,dst=/data" \
    --mount "type=bind,src=${drill_root}/key,dst=/key" \
    --mount "type=bind,src=${drill_root}/recovery,dst=/recovery" \
    --env "ROOTWELL_VOLUME_DRILL_PHASE=${phase}" \
    "$fixture_image" -test.run '^TestContainerVolumeDrill$' -test.v
}

volume_test seed "$seed_image"
volume_test reopen

docker compose -f compose.yaml -p rootwell-volume-ci up -d --no-build rootwell
curl --ipv4 --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 \
  http://localhost:4180/login >/dev/null
container_id="$(docker compose -f compose.yaml -p rootwell-volume-ci ps -q rootwell)"
mounts="$(docker inspect --format '{{range .Mounts}}{{println .Destination}}{{end}}' "$container_id" | grep -v '^$' | sort | paste -sd, -)"
if [[ "$mounts" != "/data,/key" ]]; then
  echo "server received an unexpected mount: ${mounts}" >&2
  exit 1
fi
volume_test busy
server_logs="$(docker compose -f compose.yaml -p rootwell-volume-ci logs --no-color rootwell)"
if [[ -s "$drill_root/recovery/setup-code" ]] && grep -Fq "$(cat "$drill_root/recovery/setup-code")" <<< "$server_logs"; then
  echo "the setup code leaked into server logs" >&2
  exit 1
fi
docker compose -f compose.yaml -p rootwell-volume-ci stop rootwell

chmod 0755 "$drill_root/data"
volume_test unsafe
chmod 0700 "$drill_root/data"

# A restart serves the same volume again.
docker compose -f compose.yaml -p rootwell-volume-ci up -d --no-build --force-recreate rootwell
curl --ipv4 --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 \
  http://localhost:4180/login >/dev/null
docker compose -f compose.yaml -p rootwell-volume-ci stop rootwell
echo "Disposable container volume drill passed: seed, reopen, serve, busy, unsafe and restart."
