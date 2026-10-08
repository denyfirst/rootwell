#!/usr/bin/env bash
set -euo pipefail

# CI-only disposable material. Never point this drill at an operator volume.
if [[ -z "${RUNNER_TEMP:-}" || ! -d "$RUNNER_TEMP" ]]; then
  echo "RUNNER_TEMP is required for an isolated disposable drill" >&2
  exit 1
fi
docker compose version >/dev/null
drill_root="$(mktemp -d "${RUNNER_TEMP}/rootwell-volume-XXXXXXXX")"
if [[ "$drill_root" != "${RUNNER_TEMP}/rootwell-volume-"* ]]; then
  echo "unexpected drill directory" >&2
  exit 1
fi
cleanup() {
  docker compose -f compose.yaml -p rootwell-volume-ci down --remove-orphans >/dev/null 2>&1 || true
  rm -rf -- "$drill_root"
}
trap cleanup EXIT

mkdir "$drill_root/data" "$drill_root/backup" "$drill_root/fresh" "$drill_root/recovery"
chmod 0700 "$drill_root" "$drill_root/data" "$drill_root/backup" "$drill_root/fresh" "$drill_root/recovery"
export ROOTWELL_UID="$(id -u)" ROOTWELL_GID="$(id -g)"
export ROOTWELL_DATA_DIR="$drill_root/data" ROOTWELL_BACKUP_DIR="$drill_root/backup"

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

volume_test() {
  local phase="$1"
  docker run --rm --network none --user "${ROOTWELL_UID}:${ROOTWELL_GID}" \
    --read-only --cap-drop ALL --security-opt no-new-privileges \
    --mount "type=bind,src=${drill_root}/data,dst=/data" \
    --mount "type=bind,src=${drill_root}/backup,dst=/backup" \
    --mount "type=bind,src=${drill_root}/fresh,dst=/fresh" \
    --mount "type=bind,src=${drill_root}/recovery,dst=/recovery" \
    --env "ROOTWELL_VOLUME_DRILL_PHASE=${phase}" \
    rootwell-volume-drill:ci -test.run '^TestContainerVolumeDrill$' -test.v
}

volume_test seed
volume_test reopen

docker compose -f compose.yaml -p rootwell-volume-ci up -d --no-build rootwell
curl --ipv4 --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 \
  http://localhost:4180/login >/dev/null
container_id="$(docker compose -f compose.yaml -p rootwell-volume-ci ps -q rootwell)"
mounts="$(docker inspect --format '{{range .Mounts}}{{println .Destination}}{{end}}' "$container_id")"
if [[ "$mounts" != "/data" ]]; then
  echo "server received an unexpected mount" >&2
  exit 1
fi
volume_test busy
server_logs="$(docker compose -f compose.yaml -p rootwell-volume-ci logs --no-color rootwell)"
if grep -Fq 'test-only disposable container volume password' <<< "$server_logs"; then
  echo "test password leaked into server logs" >&2
  exit 1
fi
docker compose -f compose.yaml -p rootwell-volume-ci stop rootwell

volume_test restore
chmod 0755 "$drill_root/data"
volume_test unsafe
chmod 0700 "$drill_root/data"

export ROOTWELL_DATA_DIR="$drill_root/fresh"
docker compose -f compose.yaml -p rootwell-volume-ci up -d --no-build --force-recreate rootwell
curl --ipv4 --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 \
  http://localhost:4180/login >/dev/null
docker compose -f compose.yaml -p rootwell-volume-ci stop rootwell
echo "Disposable container volume restart and fresh restore drill passed."
