#!/usr/bin/env bash
set -euo pipefail

# Lists what Docker really sends as the build context and refuses anything
# outside the reviewed source and public assets (audit RW-05). It works on a
# copy of the commit with planted secret-like files, so a broad .dockerignore
# exception fails here instead of shipping a key inside the image.
if [[ -z "${RUNNER_TEMP:-}" || ! -d "$RUNNER_TEMP" ]]; then
  echo "RUNNER_TEMP is required for a disposable build-context check" >&2
  exit 1
fi
work="$(mktemp -d "${RUNNER_TEMP}/rootwell-context-XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/source" "$work/context"
git archive HEAD | tar -xf - -C "$work/source"

planted=(
  web/workbench/planted.key
  web/workbench/planted.pfx
  web/workbench/planted.env
  web/workbench/planted.pem
  cmd/rootwelld/planted.p12
  internal/websitechain/planted.key
  internal/websitechain/testdata-planted.json
  planted.env
)
for path in "${planted[@]}"; do
  printf 'not a real secret\n' >"$work/source/$path"
done

docker build --target context --output "type=local,dest=$work/context" "$work/source"

status=0
while IFS= read -r file; do
  case "$file" in
    go.mod | go.sum) ;;
    cmd/*.go | internal/*.go) ;;
    cmd/rootwelld/auth/*.html | cmd/rootwelld/auth/*.css | cmd/rootwelld/auth/*.js) ;;
    cmd/rootwelld/auth/website-examples.json | cmd/rootwelld/auth/schibsted-grotesk.woff2) ;;
    internal/acmecertificate/staging-roots.pem | internal/acmecertificate/production-roots.pem) ;;
    web/workbench/index.html | web/workbench/style.css | web/workbench/favicon.svg) ;;
    web/workbench/app.js | web/workbench/theme.js | web/workbench/session.js | web/workbench/wasm-loader.js) ;;
    web/workbench/certificate-key-match.js | web/workbench/secret-view.js) ;;
    web/workbench/private-key.js | web/workbench/private-worker-client.js | web/workbench/private-key-worker.js) ;;
    web/workbench/pfx.js | web/workbench/pfx-worker-client.js | web/workbench/pfx-worker.js) ;;
    web/workbench/csr.js | web/workbench/csr-worker-client.js | web/workbench/csr-worker.js) ;;
    web/workbench/rootwell-demo-certificate.pem | web/workbench/rootwell-demo-bundle.pem) ;;
    web/workbench/rootwell-verify-demo-*.pem) ;;
    *)
      echo "unreviewed file in the Docker build context: $file" >&2
      status=1
      ;;
  esac
done < <(cd "$work/context" && find . -type f | sed 's|^\./||' | sort)

for path in "${planted[@]}"; do
  if [[ -e "$work/context/$path" ]]; then
    echo "planted file reached the build context: $path" >&2
    status=1
  fi
done
for required in go.mod cmd/rootwelld/main.go web/workbench/csr-worker.js internal/acmecertificate/staging-roots.pem; do
  if [[ ! -f "$work/context/$required" ]]; then
    echo "required file is missing from the build context: $required" >&2
    status=1
  fi
done
if [[ "$status" -ne 0 ]]; then
  exit "$status"
fi
echo "The Docker build context holds only reviewed source and public assets."
