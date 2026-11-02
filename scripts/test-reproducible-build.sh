#!/usr/bin/env bash
set -euo pipefail

# Development proof only: never publishes, signs, tags or reads an instance.
# Build committed source twice in different directories with independent caches.
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ||
      -z "${RUNNER_TEMP:-}" || ! -d "$RUNNER_TEMP" ]]; then
  echo "An isolated Linux amd64 runner with RUNNER_TEMP is required" >&2
  exit 1
fi
repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"
git diff --quiet
git diff --cached --quiet
commit="$(git rev-parse --verify HEAD)"
if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo "An exact committed source revision is required" >&2
  exit 1
fi

proof_root="$(mktemp -d "${RUNNER_TEMP}/rootwell-build-proof-XXXXXXXX")"
if [[ "$proof_root" != "${RUNNER_TEMP}/rootwell-build-proof-"* ]]; then
  echo "Unexpected proof directory" >&2
  exit 1
fi
cleanup() { rm -rf -- "$proof_root"; }
trap cleanup EXIT

# Resolve the pinned auto-downloaded toolchain before disabling network/toolchain
# downloads. Neither source archive may consult the operator's Go workspace.
toolchain_root="$(go env GOROOT)"
go_tool="${toolchain_root}/bin/go"
expected_go="$(sed -n 's/^go //p' go.mod)"
if [[ "$("$go_tool" env GOVERSION)" != "go${expected_go}" ]]; then
  echo "Reproducibility requires the exact go.mod toolchain" >&2
  exit 1
fi
module_cache="$(go env GOMODCACHE)"
git archive --format=tar "$commit" > "$proof_root/source.tar"
for run in first second; do
  mkdir -p "$proof_root/$run/source" "$proof_root/$run/output" "$proof_root/$run/cache"
  tar -xf "$proof_root/source.tar" -C "$proof_root/$run/source"
  (
    cd "$proof_root/$run/source"
    export GOTOOLCHAIN=local GOROOT="$toolchain_root" GOENV=off GOWORK=off
    export GOPROXY=off GOSUMDB=off GOFLAGS= CGO_ENABLED=0
    export GOCACHE="$proof_root/$run/cache" GOMODCACHE="$module_cache"
    export GOOS=linux GOARCH=amd64 GOEXPERIMENT= GOAMD64=v1
    "$go_tool" mod verify
    "$go_tool" build -trimpath -buildvcs=false -ldflags=-buildid= -o "../output/rootwell" ./cmd/rootwell
    "$go_tool" build -trimpath -buildvcs=false -ldflags=-buildid= -o "../output/rootwelld" ./cmd/rootwelld
    GOOS=js GOARCH=wasm "$go_tool" build -trimpath -buildvcs=false -ldflags=-buildid= -o "../output/rootwell.wasm" ./cmd/rootwell-browser
    cp "$toolchain_root/lib/wasm/wasm_exec.js" ../output/wasm_exec.js
  )
done

compare_outputs() {
  local name
  for name in rootwell rootwelld rootwell.wasm wasm_exec.js; do
    if ! cmp -s -- "$proof_root/first/output/$name" "$proof_root/second/output/$name"; then
      echo "Independent build outputs differ" >&2
      return 1
    fi
  done
}
compare_outputs

# Exercise the actual comparison in both directions without disabling it or
# changing product source/KDFs: a modified output and a missing output must fail.
cp "$proof_root/second/output/rootwelld" "$proof_root/second/original"
printf '\000' >> "$proof_root/second/output/rootwelld"
if compare_outputs >/dev/null 2>&1; then
  echo "Changed-output sabotage escaped comparison" >&2
  exit 1
fi
mv "$proof_root/second/original" "$proof_root/second/output/rootwelld"
mv "$proof_root/second/output/rootwell.wasm" "$proof_root/second/original-wasm"
if compare_outputs >/dev/null 2>&1; then
  echo "Missing-output sabotage escaped comparison" >&2
  exit 1
fi
mv "$proof_root/second/original-wasm" "$proof_root/second/output/rootwell.wasm"
compare_outputs
(
  cd "$proof_root/first/output"
  sha256sum rootwell rootwelld rootwell.wasm wasm_exec.js
)
echo "Independent development builds match for committed source ${commit}. No release was published."
